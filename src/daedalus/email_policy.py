"""Bounded interpretations of published SPF and DMARC DNS text records.

These helpers explain what the observed records request. They do not validate
messages, resolve SPF dependencies, or determine whether legitimate mail aligns.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any


SPF_ALL = re.compile(r"^([+\-~?]?)all$", re.IGNORECASE)
DMARC_POLICIES = {"none", "quarantine", "reject"}


def _string_records(value: Any) -> list[str] | None:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


def _unavailable_evidence(protocol: str) -> dict[str, Any]:
    assessment = {
        "status": "evidence_unavailable", "record_count": None,
        "policy": None, "label": "Evidence unavailable", "tone": "neutral",
        "summary": f"The saved {protocol} record data is incomplete or malformed; policy is unknown.",
    }
    if protocol == "DMARC":
        assessment["effective_policy"] = None
    return assessment


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
        txt_values = _string_records(records.get("TXT"))
        if txt_values is None:
            return _unavailable_evidence("SPF")
        values = [value for value in txt_values
                  if value.lstrip().casefold().startswith("v=spf1")]
    else:
        return {
            "status": "not_captured", "record_count": None,
            "policy": None, "label": "Not captured", "tone": "neutral",
            "summary": "This saved DNS snapshot does not contain an SPF lookup.",
        }

    if values is None:
        return _unavailable_evidence("SPF")
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
    if observed_values is None:
        return _unavailable_evidence("DMARC")
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


def _dkim_assessment(records: dict[str, Any], errors: dict[str, Any]) -> dict[str, Any]:
    """Describe DKIM public keys found at the selectors Daedalus probes.

    DKIM selectors cannot be enumerated from DNS, so absence at the probed
    selectors is not proof that mail is unsigned.
    """
    dkim = records.get("DKIM")
    if not isinstance(dkim, dict):
        return {"status": "not_captured", "selectors": [], "label": "Not captured", "tone": "neutral",
                "summary": "This saved DNS snapshot does not contain DKIM lookups."}
    keys, revoked = [], []
    for selector, values in sorted(dkim.items()):
        for value in _string_records(values) or []:
            tags = {}
            for part in value.split(";"):
                name, _, tag_value = part.strip().partition("=")
                tags[name.strip().lower()] = tag_value.strip()
            if tags.get("v", "DKIM1").upper() != "DKIM1" or "p" not in tags:
                continue
            if not tags["p"]:
                revoked.append(selector)
                continue
            try:
                der = base64.b64decode("".join(tags["p"].split()), validate=True)
            except (binascii.Error, ValueError):
                continue
            bits = None
            if tags.get("k", "rsa").lower() == "rsa":
                bits = 2048 if len(der) >= 270 else 1024 if len(der) >= 150 else None
            keys.append({"selector": selector, "key_type": tags.get("k", "rsa").lower(), "rsa_bits_at_least": bits})
    if keys:
        weak = [key["selector"] for key in keys if key["rsa_bits_at_least"] == 1024]
        return {"status": "published", "selectors": keys, "label": "Key published",
                "tone": "good" if not weak else "attention",
                "summary": "A DKIM public key is published at: " + ", ".join(key["selector"] for key in keys)
                           + (". A 1024-bit key was observed at: " + ", ".join(weak) if weak else ".")}
    failed = [name for name in errors if name.startswith("DKIM ")]
    if failed:
        return {"status": "lookup_failed", "selectors": [], "label": "Lookup failed", "tone": "neutral",
                "summary": "Some DKIM selector lookups failed; DKIM status is unknown."}
    if revoked:
        return {"status": "revoked", "selectors": [], "label": "Key revoked", "tone": "attention",
                "summary": "The DKIM key at " + ", ".join(revoked) + " is empty, which marks it revoked."}
    return {"status": "not_found", "selectors": [], "label": "Not found at common selectors", "tone": "neutral",
            "summary": "No DKIM key was found at the selectors Daedalus checks. Your provider may use a different selector."}


def _guidance(spf: dict[str, Any], dkim: dict[str, Any], dmarc: dict[str, Any]) -> list[dict[str, str]]:
    """Plain next steps. level: good, info, warn or action."""
    items = []
    def add(area, level, text): items.append({"area": area, "level": level, "text": text})
    status = spf.get("status")
    if status == "published":
        if spf.get("policy") == "hard_fail":
            add("SPF", "good", "SPF is published and rejects unlisted senders (-all).")
        elif spf.get("policy") == "soft_fail":
            add("SPF", "info", "SPF is published with ~all. Once every service that sends your mail is listed, tighten it to -all.")
        else:
            add("SPF", "warn", "SPF is published but does not restrict senders. End the record with ~all, then -all.")
    elif status == "not_published":
        add("SPF", "action", "No SPF record. Publish one TXT record starting v=spf1 that lists your mail services and ends in ~all.")
    elif status in {"multiple_records", "invalid_record"}:
        add("SPF", "action", "The SPF record is invalid or duplicated, which breaks SPF. Publish exactly one valid v=spf1 record.")
    else:
        add("SPF", "info", "SPF could not be assessed from this check. Run it again.")
    dstatus = dkim.get("status")
    if dstatus == "published":
        add("DKIM", "good" if dkim.get("tone") == "good" else "warn",
            "DKIM signing key found." if dkim.get("tone") == "good" else "A DKIM key is 1024-bit. Rotate to 2048-bit in your mail provider.")
    elif dstatus == "not_found":
        add("DKIM", "action", "No DKIM key at common selectors. Turn on DKIM signing in your mail provider, publish the key it gives you, and confirm it appears here.")
    elif dstatus == "revoked":
        add("DKIM", "action", "A DKIM key is revoked (empty). Publish a new key if you still send mail with that selector.")
    else:
        add("DKIM", "info", "DKIM could not be assessed from this check. Run it again.")
    mstatus = dmarc.get("status")
    if mstatus == "published":
        policy = dmarc.get("effective_policy") or dmarc.get("policy")
        if policy == "reject":
            add("DMARC", "good", "DMARC is published at reject, the strongest policy." + ("" if dmarc.get("aggregate_reporting_configured") else " Add a rua= address to receive reports."))
        elif policy == "quarantine":
            add("DMARC", "info", "DMARC is at quarantine. After reviewing reports and confirming legitimate mail passes, move to reject.")
        else:
            add("DMARC", "action", "DMARC is monitor-only (p=none). Review the reports, then move to quarantine and then reject.")
    elif mstatus == "not_published":
        add("DMARC", "action", "No DMARC record. Publish a TXT record at _dmarc with v=DMARC1; p=none; rua=mailto:you@domain to start, then tighten it.")
    elif mstatus in {"multiple_records", "invalid_record"}:
        add("DMARC", "action", "The DMARC record is invalid or duplicated. Publish exactly one valid v=DMARC1 record.")
    else:
        add("DMARC", "info", "DMARC could not be assessed from this check. Run it again.")
    return items


def analyze_email_auth(records: Any, resolver_errors: Any = None) -> dict[str, Any]:
    """Interpret observed root SPF and DMARC records without extra DNS queries."""
    if resolver_errors is not None and (
        not isinstance(resolver_errors, dict)
        or not all(isinstance(key, str) for key in resolver_errors)
    ):
        # A malformed saved error collection cannot establish successful DNS
        # lookups, even when record values themselves look valid. Legacy
        # snapshots without error metadata remain supported.
        return {
            "version": 1,
            "spf": _unavailable_evidence("SPF"),
            "dmarc": _unavailable_evidence("DMARC"),
        }
    records = records if isinstance(records, dict) else {}
    errors = resolver_errors if isinstance(resolver_errors, dict) else {}
    spf = _spf_assessment(records, errors)
    dkim = _dkim_assessment(records, errors)
    dmarc = _dmarc_assessment(records, errors)
    return {
        "version": 1,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "guidance": _guidance(spf, dkim, dmarc),
    }
