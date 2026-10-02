"""Bounded interpretations of published SPF and DMARC DNS text records.

These helpers explain what the observed records request. They do not validate
messages, resolve SPF dependencies, or determine whether legitimate mail aligns.
"""

from __future__ import annotations

import re
from typing import Any


SPF_ALL = re.compile(r"^([+\-~?]?)all$", re.IGNORECASE)
DMARC_POLICIES = {"none", "quarantine", "reject"}


def _string_records(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _spf_assessment(records: dict[str, Any], errors: dict[str, Any]) -> dict[str, Any]:
    if "TXT" in errors:
        return {
            "status": "lookup_failed", "record_count": None,
            "policy": None, "label": "Lookup failed", "tone": "neutral",
            "summary": "The root TXT lookup failed; SPF policy is unknown.",
        }
    if "SPF" in records:
        values = _string_records(records.get("SPF"))
    elif "TXT" in records:
        values = [value for value in _string_records(records.get("TXT"))
                  if value.lstrip().casefold().startswith("v=spf1")]
    else:
        return {
            "status": "not_captured", "record_count": None,
            "policy": None, "label": "Not captured", "tone": "neutral",
            "summary": "This saved DNS snapshot does not contain an SPF lookup.",
        }

    if not values:
        return {
            "status": "not_published", "record_count": 0,
            "policy": None, "label": "Not published", "tone": "attention",
            "summary": "No SPF record was observed at the domain root.",
        }
    if len(values) != 1:
        return {
            "status": "multiple_records", "record_count": len(values),
            "policy": None, "label": "Multiple records", "tone": "attention",
            "summary": "Multiple SPF records were observed; SPF permits only one policy record per name.",
        }

    terms = values[0].strip().split()
    # RFC 7208 requires the TXT string to start with the version token. The
    # leading-space tolerant candidate lookup above is useful for explaining
    # malformed SPF-looking values, but must not turn one into a valid policy.
    if not terms or terms[0].casefold() != "v=spf1" or not values[0].casefold().startswith("v=spf1"):
        return {
            "status": "invalid_record", "record_count": 1,
            "policy": None, "label": "Malformed record", "tone": "attention",
            "summary": "The observed TXT value does not start with the SPF version token.",
        }

    all_qualifier = None
    redirect_before_all = False
    for term in terms[1:]:
        match = SPF_ALL.fullmatch(term)
        if match:
            all_qualifier = match.group(1) or "+"
            break
        if term.casefold().startswith("redirect="):
            redirect_before_all = True

    behavior = {
        "-": ("hard_fail", "Hard fail", "A -all mechanism is observed. It requests Fail when reached; earlier mechanisms and sender outcomes were not evaluated."),
        "~": ("soft_fail", "Soft fail", "A ~all mechanism is observed. It requests SoftFail when reached; earlier mechanisms and sender outcomes were not evaluated."),
        "?": ("neutral", "Neutral", "A ?all mechanism is observed. It requests Neutral when reached; earlier mechanisms and sender outcomes were not evaluated."),
        "+": ("pass_all", "Allows all", "A +all mechanism is observed; it passes senders that reach it and expresses no restriction for them."),
    }
    if all_qualifier is not None:
        policy, label, summary = behavior[all_qualifier]
        tone = "good" if policy == "hard_fail" else "attention" if policy == "pass_all" else "neutral"
        return {
            "status": "published", "record_count": 1, "policy": policy,
            "all_qualifier": all_qualifier, "label": label, "tone": tone,
            "summary": summary,
        }
    if redirect_before_all:
        return {
            "status": "published", "record_count": 1,
            "policy": "redirect_unresolved", "all_qualifier": None,
            "label": "Redirect not evaluated", "tone": "neutral",
            "summary": "The SPF record delegates with redirect=; the target and its policy were not evaluated.",
        }
    return {
        "status": "published", "record_count": 1,
        "policy": "no_explicit_all", "all_qualifier": None,
        "label": "No explicit default", "tone": "attention",
        "summary": "No effective all mechanism was observed; referenced DNS terms and sender outcomes were not evaluated.",
    }


def _dmarc_tags(value: str) -> dict[str, str] | None:
    parts = [part.strip() for part in value.split(";")]
    if not parts or parts[0].casefold() != "v=dmarc1":
        return None
    if any(not part for part in parts[1:-1]):
        return None
    tags: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            continue
        key, separator, tag_value = part.partition("=")
        key = key.strip().casefold()
        if not separator or not key or not key.isascii() or not key.isalpha() or key in tags:
            return None
        tag_value = tag_value.strip()
        if not tag_value:
            return None
        tags[key] = tag_value
    return tags


def _effective_policy(policy: str, test_mode: bool) -> str:
    if not test_mode or policy == "none":
        return policy
    return "quarantine" if policy == "reject" else "none"


def _dmarc_assessment(records: dict[str, Any], errors: dict[str, Any]) -> dict[str, Any]:
    if "DMARC" in errors:
        return {
            "status": "lookup_failed", "record_count": None,
            "policy": None, "effective_policy": None,
            "label": "Lookup failed", "tone": "neutral",
            "summary": "The _dmarc TXT lookup failed; DMARC policy is unknown.",
        }
    if "DMARC" not in records:
        return {
            "status": "not_captured", "record_count": None,
            "policy": None, "effective_policy": None,
            "label": "Not captured", "tone": "neutral",
            "summary": "This saved DNS snapshot does not contain a DMARC lookup.",
        }
    observed_values = _string_records(records.get("DMARC"))
    values = [value for value in observed_values if value.lstrip().casefold().startswith("v=dmarc1")]
    if not values:
        malformed = any(
            "v=dmarc1" in value.casefold()
            or value.lstrip().casefold().startswith("v=")
            for value in observed_values
        )
        if malformed:
            return {
                "status": "invalid_record", "record_count": len(observed_values),
                "policy": None, "effective_policy": None,
                "label": "Malformed record", "tone": "attention",
                "summary": "No _dmarc TXT value starts with the current DMARC version tag.",
            }
        return {
            "status": "not_published", "record_count": 0,
            "policy": None, "effective_policy": None,
            "label": "Not published", "tone": "attention",
            "summary": "No DMARC policy record was observed at _dmarc.",
        }
    if len(values) != 1:
        return {
            "status": "multiple_records", "record_count": len(values),
            "policy": None, "effective_policy": None,
            "label": "Multiple records", "tone": "attention",
            "summary": "Multiple DMARC policy records were observed; policy discovery discards multiple records at one name.",
        }
    tags = _dmarc_tags(values[0])
    if tags is None:
        return {
            "status": "invalid_record", "record_count": 1,
            "policy": None, "effective_policy": None,
            "label": "Malformed record", "tone": "attention",
            "summary": "The observed TXT value is not a single parseable DMARC1 tag list.",
        }

    warnings: list[str] = []
    # RFC 9989 makes p optional: a syntactically valid record without p acts
    # as p=none. Invalid known policy values are ignored in favor of defaults.
    policy = tags.get("p", "none").casefold()
    if policy not in DMARC_POLICIES:
        warnings.append("Invalid p tag ignored; defaulting to none.")
        policy = "none"
    sp = tags.get("sp", "").casefold()
    if sp and sp not in DMARC_POLICIES:
        warnings.append("Invalid sp tag ignored; inheriting p.")
        sp = ""
    np = tags.get("np", "").casefold()
    if np and np not in DMARC_POLICIES:
        warnings.append("Invalid np tag ignored; inheriting the subdomain policy.")
        np = ""
    subdomain_policy = sp or policy
    nonexistent_policy = np or subdomain_policy

    test_value = tags.get("t", "n").casefold()
    test_mode = test_value == "y"
    if test_value not in {"y", "n"}:
        warnings.append("Invalid t tag ignored; defaulting to normal policy mode.")
        test_mode = False
    effective = _effective_policy(policy, test_mode)
    effective_sp = _effective_policy(subdomain_policy, test_mode)
    effective_np = _effective_policy(nonexistent_policy, test_mode)

    alignment: dict[str, str] = {}
    for tag in ("aspf", "adkim"):
        value = tags.get(tag, "r").casefold()
        if value not in {"r", "s"}:
            warnings.append(f"Invalid {tag} tag ignored; defaulting to relaxed alignment.")
            value = "r"
        alignment[tag] = "strict" if value == "s" else "relaxed"

    aggregate_reporting = bool(tags.get("rua", "").strip())
    policy_labels = {"none": "Monitor only", "quarantine": "Quarantine", "reject": "Reject"}
    if test_mode:
        label = "Testing: " + policy_labels[effective]
        summary = f"Test mode lowers the declared {policy} policy to {effective} for message handling."
        tone = "neutral"
    else:
        label = policy_labels[effective]
        summary = f"Requests {effective} handling for messages that fail DMARC."
        tone = "good" if effective in {"quarantine", "reject"} else "neutral"
    summary += " Aggregate reports are requested." if aggregate_reporting else " No aggregate-report URI is configured."
    if warnings:
        summary += " " + " ".join(warnings)
    if "pct" in tags:
        summary += " The legacy pct tag is not applied by the current assessment."

    return {
        "status": "published", "record_count": 1,
        "policy": policy, "effective_policy": effective,
        "subdomain_policy": subdomain_policy,
        "effective_subdomain_policy": effective_sp,
        "nonexistent_subdomain_policy": nonexistent_policy,
        "effective_nonexistent_subdomain_policy": effective_np,
        "test_mode": test_mode,
        "alignment": alignment,
        "aggregate_reporting_configured": aggregate_reporting,
        "legacy_pct_present": "pct" in tags,
        "warnings": warnings,
        "label": label, "tone": tone, "summary": summary,
    }


def analyze_email_auth(records: Any, resolver_errors: Any = None) -> dict[str, Any]:
    """Interpret observed root SPF and DMARC records without extra DNS queries."""
    records = records if isinstance(records, dict) else {}
    errors = resolver_errors if isinstance(resolver_errors, dict) else {}
    return {
        "version": 1,
        "spf": _spf_assessment(records, errors),
        "dmarc": _dmarc_assessment(records, errors),
    }
