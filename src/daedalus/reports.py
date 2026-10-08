from __future__ import annotations

import io
import math
import re
from datetime import UTC, datetime
from html import escape
from typing import Any
from urllib.parse import urlsplit

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import KeepTogether, LongTable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from daedalus.email_policy import analyze_email_auth


OLIVE_950 = colors.HexColor("#1f2117")
OLIVE_800 = colors.HexColor("#464a34")
OLIVE_600 = colors.HexColor("#6e754b")
OLIVE_100 = colors.HexColor("#eef0e6")
OLIVE_050 = colors.HexColor("#f7f8f4")
INK = colors.HexColor("#29291f")
MUTED = colors.HexColor("#737366")
LINE = colors.HexColor("#d9dccb")
WHITE = colors.white


def _text(value: Any) -> str:
    if value is None:
        return "Not reported"
    if isinstance(value, dict):
        return "\n".join(
            f"{key}: {_text(item)}"
            for key, item in sorted(value.items(), key=lambda row: str(row[0]))
        ) or "Not reported"
    if isinstance(value, (list, tuple)):
        items = [_text(item) for item in value if item is not None]
        if not items:
            return "Not reported"
        inline = ", ".join(items)
        return inline if len(inline) <= 120 else "\n".join(items)
    return str(value)


def _time_text(value: Any) -> str:
    if not value:
        return "Not recorded"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return _text(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return (
        parsed.astimezone(UTC)
        .strftime("%b %d, %Y at %H:%M UTC")
        .replace(" 0", " ")
    )


def _tls_valid_at_collection(tls: Any, run: dict[str, Any]) -> bool | None:
    """Assess the captured certificate dates at the successful check time."""
    if not isinstance(tls, dict):
        return None
    try:
        starts = datetime.fromisoformat(str(tls["valid_from"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(tls["valid_until"]).replace("Z", "+00:00"))
        observed = datetime.fromisoformat(str(run["completed_at"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        return None
    if starts.tzinfo is None:
        starts = starts.replace(tzinfo=UTC)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=UTC)
    return starts <= observed <= expires


def _change_field_label(field_path: Any) -> str:
    """Turn stored machine paths into concise labels in exported reports."""
    path = str(field_path or "Unknown field")
    labels = {
        "page_content.sampled_bytes": "Page content size",
        "page_content.sha256": "Page content fingerprint",
    }
    if path in labels:
        return labels[path]
    if path.startswith("records."):
        record = path.removeprefix("records.")
        return "DNS record " + record.replace("WWW_", "www ").replace("_", " ")
    if path.startswith("resolver_errors."):
        return "DNS lookup " + path.removeprefix("resolver_errors.") + " status"
    return path.replace("_", " ").replace(".", " · ").strip().capitalize()


def _tls_issuer_text(value: Any) -> str:
    if not isinstance(value, str):
        return _text(value)
    fields = {}
    for part in value.split(","):
        if "=" in part:
            key, item = part.split("=", 1)
            fields[key.strip()] = item.strip()
    preferred = [
        fields.get("organizationName"),
        fields.get("commonName"),
        fields.get("countryName"),
    ]
    return " · ".join(item for item in preferred if item) or value


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    safe = escape(_text(value)).replace("\n", "<br/>")
    return Paragraph(safe, style)


def _table(data: list[list[Any]], widths: list[float], *, header: bool = True) -> LongTable:
    table = LongTable(data, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("BACKGROUND", (0, 0), (-1, 0), OLIVE_100 if header else WHITE),
    ]
    if header:
        commands.extend([
            ("TEXTCOLOR", (0, 0), (-1, 0), OLIVE_950),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ])
        for row in range(1, len(data)):
            if row % 2 == 0:
                commands.append(("BACKGROUND", (0, row), (-1, row), OLIVE_050))
    table.setStyle(TableStyle(commands))
    return table


def _record_value(records: dict[str, Any], errors: dict[str, str], key: str) -> tuple[str, str]:
    if key.startswith("DKIM."):
        selector = key.removeprefix("DKIM.")
        value = (records.get("DKIM") or {}).get(selector)
        lookup = "DKIM " + selector
    elif key.startswith("WWW_"):
        value = records.get(key)
        lookup = "www " + key.removeprefix("WWW_").upper()
    else:
        value = records.get(key)
        lookup = key
    if lookup in errors:
        return "Lookup failed: " + errors[lookup], "Unknown"
    if value in (None, [], ""):
        return "Not published", "Not found"
    return _text(value), "Published"


def _append_latest_attempt(story: list[Any], check: dict[str, Any], styles: dict[str, ParagraphStyle]) -> None:
    attempt = check.get("latest_attempt")
    saved = check.get("run") or {}
    if not isinstance(attempt, dict) or attempt.get("id") == saved.get("id"):
        return
    status = attempt.get("status") or "unknown"
    timing = (f"queued {_time_text(attempt['queued_at'])}" if attempt.get("queued_at") else f"started {_time_text(attempt.get('started_at'))}")
    if attempt.get("collection_started_at"):
        timing += f" · collection started {_time_text(attempt['collection_started_at'])}"
    story.append(_paragraph(
        f"Latest attempt #{attempt.get('id')}: {status} · {timing}. "
        + (f"Evidence below is from saved successful run #{saved.get('id')}." if saved else "No successful evidence is available."),
        styles["body"],
    ))
    if attempt.get("error_summary"):
        story.append(_paragraph("Latest attempt warning: " + str(attempt["error_summary"]), styles["small"]))


def _append_email_assessment(
    story: list[Any], snapshot: dict[str, Any], records: dict[str, Any],
    errors: dict[str, Any], styles: dict[str, ParagraphStyle],
) -> None:
    assessment = snapshot.get("email_authentication_assessment")
    if not isinstance(assessment, dict):
        assessment = analyze_email_auth(records, errors)
    spf = assessment.get("spf") if isinstance(assessment.get("spf"), dict) else {}
    dmarc = assessment.get("dmarc") if isinstance(assessment.get("dmarc"), dict) else {}
    alignment = dmarc.get("alignment") if isinstance(dmarc.get("alignment"), dict) else {}
    subdomain = dmarc.get("effective_subdomain_policy") or dmarc.get("subdomain_policy")
    nonexistent = dmarc.get("effective_nonexistent_subdomain_policy") or dmarc.get("nonexistent_subdomain_policy")
    rows: list[list[Any]] = [[
        _paragraph("Control", styles["table_header"]),
        _paragraph("Observed interpretation", styles["table_header"]),
        _paragraph("Scope and limits", styles["table_header"]),
    ]]
    rows.append([
        _paragraph("SPF", styles["cell"]),
        _paragraph(spf.get("label") or "Unknown", styles["cell"]),
        _paragraph(spf.get("summary") or "No SPF interpretation is available.", styles["cell"]),
    ])
    rows.append([
        _paragraph("DMARC", styles["cell"]),
        _paragraph(dmarc.get("label") or "Unknown", styles["cell"]),
        _paragraph(dmarc.get("summary") or "No DMARC interpretation is available.", styles["cell"]),
    ])
    if dmarc.get("status") == "published":
        alignment_text = (
            "Alignment: SPF " + str(alignment.get("aspf") or "relaxed")
            + "; DKIM " + str(alignment.get("adkim") or "relaxed") + "."
        )
        coverage = (
            "Existing subdomains: " + str(subdomain or "Unknown")
            + "; nonexistent subdomains: " + str(nonexistent or "Unknown")
            + ". " + alignment_text
        )
        rows.append([
            _paragraph("DMARC scope", styles["cell"]),
            _paragraph("Aggregate reports requested" if dmarc.get("aggregate_reporting_configured") else "No aggregate report URI", styles["cell"]),
            _paragraph(coverage, styles["cell"]),
        ])
    full = assessment if isinstance(assessment.get("guidance"), list) else analyze_email_auth(records, errors)
    dkim = full.get("dkim") if isinstance(full.get("dkim"), dict) else {}
    rows.insert(2, [
        _paragraph("DKIM", styles["cell"]),
        _paragraph(dkim.get("label") or "Unknown", styles["cell"]),
        _paragraph(dkim.get("summary") or "No DKIM interpretation is available.", styles["cell"]),
    ])
    story.append(Paragraph("Email authentication interpretation", styles["subsection"]))
    story.append(_paragraph(
        "This interprets the published DNS text only. Daedalus does not send or inspect email, recursively evaluate SPF dependencies, or verify actual SPF/DKIM alignment.",
        styles["small"],
    ))
    story.append(_table(rows, [1.0 * inch, 1.35 * inch, 4.15 * inch]))
    guidance = [item for item in full.get("guidance") or [] if isinstance(item, dict)]
    if guidance:
        labels = {"good": "OK", "info": "Consider", "warn": "Review", "action": "Fix"}
        steps = [[_paragraph("Control", styles["table_header"]), _paragraph("Next step", styles["table_header"]),
                  _paragraph("What to do", styles["table_header"])]]
        for item in guidance:
            steps.append([_paragraph(item.get("area"), styles["cell"]),
                          _paragraph(labels.get(item.get("level"), "Review"), styles["cell"]),
                          _paragraph(item.get("text"), styles["cell"])])
        story.append(Paragraph("What to do next", styles["subsection"]))
        story.append(_table(steps, [1.0 * inch, 1.0 * inch, 4.5 * inch]))


def _append_dns(story: list[Any], check: dict[str, Any], styles: dict[str, ParagraphStyle]) -> None:
    story.append(Paragraph("DNS and email health", ParagraphStyle(name="DNSSection", parent=styles["section"], keepWithNext=False)))
    _append_latest_attempt(story, check, styles)
    run = check.get("run")
    if not run:
        story.append(_paragraph("No saved DNS check is available for this workspace.", styles["body"]))
        return
    _append_run_line(story, run, styles)
    snapshot = run.get("snapshot") or {}
    records = snapshot.get("records") or {}
    errors = snapshot.get("resolver_errors") or {}
    _append_email_assessment(story, snapshot, records, errors, styles)
    rows: list[list[Any]] = [[_paragraph("Record", styles["table_header"]), _paragraph("Observed value", styles["table_header"]), _paragraph("Status", styles["table_header"])]]
    record_keys = ["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "CAA", "DS", "DNSKEY", "WWW_A", "WWW_AAAA", "WWW_CNAME", "SPF", "DMARC"]
    for key in record_keys:
        value, status = _record_value(records, errors, key)
        if key in {"CNAME", "SOA", "DS", "DNSKEY"} and key not in records:
            value, status = "Not collected in this saved run", "Not checked"
        rows.append([
            _paragraph(key.replace("WWW_", "www "), styles["cell"]),
            _paragraph(value, styles["cell"]),
            _paragraph(status, styles["cell"]),
        ])
    dkim = records.get("DKIM") or {}
    for selector in sorted(dkim):
        value, status = _record_value(records, errors, "DKIM." + selector)
        rows.append([
            _paragraph("DKIM " + selector, styles["cell"]),
            _paragraph(value, styles["cell"]),
            _paragraph(status, styles["cell"]),
        ])
    story.append(_table(rows, [1.15 * inch, 4.55 * inch, 0.8 * inch]))
    dnssec = snapshot.get("dnssec_observations")
    if isinstance(dnssec, dict):
        story.append(Spacer(1, 6))
        assessment = {"lookup_incomplete": "Lookup incomplete", "records_observed": "Signing records observed", "no_records_observed": "No signing records observed"}.get(dnssec.get("assessment"), "Unknown")
        story.append(_paragraph("DNSSEC observations: " + assessment + ". Resolver authentication flags are upstream observations; Daedalus did not validate the DNSSEC chain locally.", styles["body"]))
        story.append(_paragraph("Resolver AD flags: " + _text(dnssec.get("resolver_ad_by_query")), styles["small"]))
    observations = snapshot.get("query_observations")
    if isinstance(observations, dict) and observations:
        story.append(Paragraph("DNS lookup evidence", styles["subsection"]))
        story.append(_paragraph("TTL is the remaining resolver cache lifetime, not necessarily the configured authoritative TTL. TTL-only changes do not trigger alerts. AD is an upstream resolver assertion.", styles["small"]))
        query_rows = [[_paragraph(label, styles["table_header"]) for label in ("Query / canonical name", "Result", "Remaining TTL", "Upstream AD")]]
        for key, observation in sorted(observations.items())[:50]:
            ttl = observation.get("observed_ttl_seconds")
            ad = observation.get("resolver_ad")
            query_rows.append([_paragraph(f"{observation.get('query_name')} / {observation.get('record_type')}\nCanonical: {observation.get('canonical_name') or 'Unknown'}", styles["cell"]),
                _paragraph(str(observation.get("status") or "unknown").replace("_", " "), styles["cell"]),
                _paragraph(f"{ttl} seconds" if type(ttl) is int else "Unknown", styles["cell"]),
                _paragraph("Asserted" if ad is True else "Not asserted" if ad is False else "Unknown", styles["cell"])])
        story.append(_table(query_rows, [3.1 * inch, .9 * inch, 1.1 * inch, 1.4 * inch]))
        if len(observations) > 50:
            story.append(_paragraph("Additional query observations remain in the saved snapshot.", styles["small"]))
    if errors:
        story.append(Spacer(1, 6))
        warnings = "; ".join(f"{name}: {error}" for name, error in sorted(errors.items()))
        story.append(_paragraph("Resolver warnings: " + warnings, styles["small"]))
    _append_changes(story, check.get("changes") or [], styles)


def _append_active_website(story: list[Any], check: dict[str, Any], styles: dict[str, ParagraphStyle]) -> None:
    section: list[Any] = [Paragraph("Bounded website exposure observations", styles["section"])]
    _append_latest_attempt(section, check, styles)
    run = check.get("run")
    if not run or not run.get("snapshot"):
        section.append(_paragraph("No saved bounded exposure-check evidence is available.", styles["body"]))
        story.append(KeepTogether(section))
        return
    _append_run_line(section, run, styles)
    snapshot = run["snapshot"]
    baseline = snapshot.get("baseline") or {}
    summary = [
        [_paragraph("Coverage", styles["table_header"]), _paragraph("Observation", styles["table_header"])],
        [_paragraph("Fixed preset", styles["cell"]), _paragraph(snapshot.get("preset_version") or "Unknown", styles["cell"])],
        [_paragraph("Coverage complete", styles["cell"]), _paragraph("Yes" if snapshot.get("coverage_complete") is True else "No · findings cannot be resolved from this run", styles["cell"])],
        [_paragraph("Missing-page baseline", styles["cell"]), _paragraph(baseline.get("assessment") or "Unknown", styles["cell"])],
    ]
    section.append(_table(summary, [1.8 * inch, 4.7 * inch]))
    probe_rows = [[_paragraph(label, styles["table_header"]) for label in ("Path", "HTTP", "Assessment", "Status")]]
    for probe in snapshot.get("probes") or []:
        probe_rows.append([_paragraph(probe.get("path") or "Unknown", styles["cell"]), _paragraph(probe.get("http_status") if probe.get("http_status") is not None else "Unknown", styles["cell"]), _paragraph(probe.get("assessment") or "unassessed", styles["cell"]), _paragraph(probe.get("error_code") or "None", styles["cell"])])
    if len(probe_rows) > 1:
        section.append(_table(probe_rows, [2.2 * inch, .65 * inch, 2.0 * inch, 1.65 * inch]))
    # Keep the section heading, coverage summary, and complete fixed-path table
    # together so a page break cannot strand only part of the probe list.
    story.append(KeepTogether(section))
    findings = snapshot.get("findings") or []
    story.append(Paragraph("Signature observations requiring review", styles["subsection"]))
    if findings:
        finding_rows = [[_paragraph(label, styles["table_header"]) for label in ("Signature", "Path", "HTTP", "Confidence")]]
        for finding in findings:
            finding_rows.append([_paragraph(finding.get("signature_id") or "Unknown", styles["cell"]), _paragraph(finding.get("path") or "Unknown", styles["cell"]), _paragraph(finding.get("http_status") if finding.get("http_status") is not None else "Unknown", styles["cell"]), _paragraph(finding.get("evidence_confidence") or "Unknown", styles["cell"])])
        story.append(_table(finding_rows, [1.7 * inch, 1.75 * inch, .6 * inch, 2.45 * inch]))
    else:
        story.append(_paragraph("No configured exposure signature was observed. This does not establish that the website is vulnerability-free.", styles["body"]))
    for limitation in snapshot.get("limitations") or []:
        story.append(_paragraph(limitation, styles["small"]))
    _append_changes(story, check.get("changes") or [], styles)


def _dependency_origin_evidence(snapshot: dict[str, Any], resource: dict[str, Any]) -> str:
    block = snapshot.get("dependency_origin_observations")
    if not isinstance(block, dict) or block.get("schema_version") != 1 or not isinstance(block.get("origins"), list):
        return "Origin attributes not recorded"
    matches = [origin for origin in block["origins"] if isinstance(origin, dict) and all(origin.get(key) == resource.get(key) for key in ("host", "scheme", "port"))]
    keys = ("http_reference_count", "script_reference_count", "stylesheet_reference_count", "integrity_declared_reference_count", "integrity_missing_reference_count")
    if len(matches) != 1 or not all(type(matches[0].get(key)) is int and 0 <= matches[0][key] <= 9007199254740991 for key in keys):
        return "Origin attributes unavailable"
    origin = matches[0]
    return (f"{origin['http_reference_count']} HTTP; {origin['script_reference_count']} script(s); "
            f"{origin['stylesheet_reference_count']} stylesheet(s); integrity: "
            f"{origin['integrity_declared_reference_count']} declared, {origin['integrity_missing_reference_count']} not declared")


def _append_website(story: list[Any], check: dict[str, Any], styles: dict[str, ParagraphStyle]) -> None:
    story.append(Paragraph("Website health and linked vendors", styles["section"]))
    _append_latest_attempt(story, check, styles)
    run = check.get("run")
    if not run:
        story.append(_paragraph("No saved website check is available for this workspace.", styles["body"]))
        return
    _append_run_line(story, run, styles)
    snapshot = run.get("snapshot") or {}
    tls = snapshot.get("tls") or {}
    summary_rows = [
        [_paragraph("Measure", styles["table_header"]), _paragraph("Observed result", styles["table_header"])],
        [_paragraph("Requested URL", styles["cell"]), _paragraph(snapshot.get("requested_url"), styles["cell"])],
        [_paragraph("Final URL", styles["cell"]), _paragraph(snapshot.get("final_url"), styles["cell"])],
        [_paragraph("HTTP response", styles["cell"]), _paragraph(f"{snapshot.get('http_status', 'Not reported')} {snapshot.get('http_reason', '')}".strip(), styles["cell"])],
        [_paragraph("Page title", styles["cell"]), _paragraph(snapshot.get("title") or "No page title returned", styles["cell"])],
        [_paragraph("TLS issuer", styles["cell"]), _paragraph(_tls_issuer_text(tls.get("issuer")), styles["cell"])],
        [_paragraph("Certificate expires", styles["cell"]), _paragraph(_time_text(tls.get("valid_until")), styles["cell"])],
        [_paragraph("Destination addresses", styles["cell"]), _paragraph(snapshot.get("destination_addresses") or "Not reported", styles["cell"])],
    ]
    if "negotiated_protocol" in tls:
        summary_rows.append([_paragraph("Negotiated TLS", styles["cell"]), _paragraph(f"{tls.get('negotiated_protocol') or 'Unknown'} · {tls.get('negotiated_cipher') or 'Unknown cipher'}", styles["cell"])])
    story.append(_table(summary_rows, [1.55 * inch, 4.95 * inch]))

    headers = snapshot.get("security_headers") or {}
    story.append(Paragraph("Security headers", styles["subsection"]))
    header_rows = [[_paragraph("Header", styles["table_header"]), _paragraph("Value", styles["table_header"])]]
    for name, value in sorted(headers.items()):
        header_rows.append([
            _paragraph(name.title(), styles["cell"]),
            _paragraph(value or "Not set", styles["cell"]),
        ])
    story.append(_table(header_rows, [2.0 * inch, 4.5 * inch]))

    observations = snapshot.get("header_observations")
    if isinstance(observations, dict):
        story.append(Paragraph("Header token observations", styles["subsection"]))
        observed_rows = [[_paragraph("Header family", styles["table_header"]), _paragraph("Recognized observations", styles["table_header"])]]
        for key, label in (("hsts", "HSTS"), ("csp", "Content Security Policy"), ("x_content_type_options", "Content type options"), ("x_frame_options", "Frame options")):
            observed_rows.append([_paragraph(label, styles["cell"]), _paragraph(observations.get(key) or "Not collected", styles["cell"])])
        story.append(_table(observed_rows, [2 * inch, 4.5 * inch]))
        story.append(_paragraph("Recognized response-header tokens only; these observations do not prove effective browser enforcement. HSTS max-age zero disables the policy. A preload token does not prove preload-list membership. " + ("Analysis is partial." if observations.get("analysis_partial") else ""), styles["small"]))

    cookies = snapshot.get("cookie_observations")
    if isinstance(cookies, dict):
        story.append(Paragraph("Cookie attributes", styles["subsection"]))
        cookie_rows = [[_paragraph("Observation", styles["table_header"]), _paragraph("Count", styles["table_header"])]]
        for key, label in (("response_header_count", "Set-Cookie response headers"), ("inspected_cookie_count", "Inspected cookies"), ("secure_attribute_count", "Secure attribute"), ("http_only_attribute_count", "HttpOnly attribute"), ("same_site_strict_count", "SameSite Strict"), ("same_site_lax_count", "SameSite Lax"), ("same_site_none_count", "SameSite None"), ("same_site_missing_count", "SameSite absent"), ("same_site_none_without_secure_count", "SameSite None without Secure"), ("unparsed_header_count", "Unparsed headers")):
            cookie_rows.append([_paragraph(label, styles["cell"]), _paragraph(cookies.get(key, "Unknown"), styles["cell"])])
        story.append(_table(cookie_rows, [4.95 * inch, 1.55 * inch]))
        story.append(_paragraph("Final response headers only; cookie names and values are not retained. " + ("Analysis is partial." if cookies.get("analysis_partial") else "These counts do not assess effective browser behavior."), styles["small"]))
    content = snapshot.get("page_content")
    if isinstance(content, dict):
        story.append(Paragraph("Fetched page evidence", styles["subsection"]))
        story.append(_paragraph(f"SHA-256: {content.get('sha256') or 'Unknown'}", styles["cell"]))
        story.append(_paragraph(f"Captured {content.get('sampled_bytes', 'Unknown')} bytes; partial: {content.get('partial', 'Unknown')}; eligible for content comparison: {content.get('comparison_eligible', 'Unknown')}. Dynamic content can change legitimately; a changed digest is not evidence of defacement. Only matching URLs and content types with complete eligible responses are compared.", styles["small"]))
    if "negotiated_protocol" in tls:
        story.append(_paragraph("TLS details describe one validated connection, not an enumeration of supported protocols or ciphers.", styles["small"]))

    resources = snapshot.get("external_resources")
    story.append(Paragraph("Linked vendors and external resources", styles["subsection"]))
    dependencies = snapshot.get("dependency_observations") or {}
    if dependencies.get("schema_version") == 1:
        dependency_rows = [[_paragraph("Root-page dependency observation", styles["table_header"]), _paragraph("Count", styles["table_header"])]]
        for label, key in (("HTTP references", "http_reference_count"), ("External scripts", "script_reference_count"), ("External stylesheets", "stylesheet_reference_count"), ("Script/style integrity declared", "integrity_declared_reference_count"), ("Script/style integrity not declared", "integrity_missing_reference_count")):
            count = dependencies.get(key)
            dependency_rows.append([_paragraph(label, styles["cell"]), _paragraph(count if type(count) is int and count >= 0 else "Unknown", styles["cell"])])
        story.append(_table(dependency_rows, [4.95 * inch, 1.55 * inch]))
        story.append(_paragraph("Returned HTML attributes only. Integrity declarations are not validated; missing metadata needs context and does not prove a vulnerable dependency. Linked content and vendor security were not assessed.", styles["small"]))

    if resources is None:
        story.append(_paragraph("This saved run predates the linked-resource inventory. Run another website check to collect it.", styles["body"]))
    elif not resources:
        story.append(_paragraph("No third-party resources were found in the captured root-page HTML.", styles["body"]))
    else:
        resource_rows = [[
            _paragraph("Vendor", styles["table_header"]),
            _paragraph("Host", styles["table_header"]),
            _paragraph("Linked resource types", styles["table_header"]),
            _paragraph("Transport", styles["table_header"]),
        ]]
        for resource in resources:
            host = resource.get("host", "Unknown host")
            if resource.get("port"):
                host += ":" + str(resource["port"])
            resource_rows.append([
                _paragraph(resource.get("vendor") or "Unclassified", styles["cell"]),
                _paragraph(host, styles["cell"]),
                _paragraph(_text(resource.get("resource_types") or []) + "\n" + _dependency_origin_evidence(snapshot, resource), styles["cell"]),
                _paragraph((resource.get("scheme") or "unknown").upper(), styles["cell"]),
            ])
        story.append(_table(resource_rows, [1.45 * inch, 1.8 * inch, 2.35 * inch, 0.9 * inch]))
        if snapshot.get("external_resources_truncated"):
            story.append(_paragraph("The stored inventory was capped at 100 linked origins.", styles["small"]))
    if snapshot.get("page_html_truncated"):
        story.append(_paragraph("The page exceeded 256 KiB; resource inventory covers only the captured first 256 KiB.", styles["small"]))
    reviews = check.get("vendor_reviews")
    story.append(Paragraph("Dependency review decisions", styles["subsection"]))
    if not isinstance(reviews, dict):
        story.append(_paragraph("Review decisions were not captured in this report snapshot.", styles["body"]))
    else:
        story.append(_paragraph(f"Decisions apply to saved website inventory #{reviews.get('run_id')}. These are human review records, not provider security assessments or approvals. Later decisions do not change this PDF.", styles["body"]))
        latest = reviews.get("latest") or []
        if not latest:
            story.append(_paragraph("No decisions were recorded for this inventory when the report was requested.", styles["body"]))
        else:
            rows = [[_paragraph(label, styles["table_header"]) for label in ("Origin", "Decision", "Reviewer", "Recorded")]]
            labels = {"reviewed": "Reviewed", "needs_action": "Needs action", "monitor": "Monitor"}
            for review in latest:
                origin = review.get("origin") or {}
                host = str(origin.get("host") or "Unknown") + (":" + str(origin["port"]) if origin.get("port") else "")
                rows.append([_paragraph(host, styles["cell"]), _paragraph(labels.get(review.get("status"), "Unknown"), styles["cell"]), _paragraph(review.get("reviewer") or "Former member", styles["cell"]), _paragraph(_time_text(review.get("created_at")), styles["cell"])])
            story.append(_table(rows, [1.9 * inch, 1.0 * inch, 1.5 * inch, 2.1 * inch]))
        history = reviews.get("history") or []
        history_ids = {review.get("id") for review in history}
        older_current = [review for review in latest if review.get("id") not in history_ids]
        if older_current:
            story.append(Paragraph("Current decisions outside recent history", styles["subsection"]))
            for review in older_current:
                origin = review.get("origin") or {}
                story.append(_paragraph(f"Review #{review.get('id')} - {origin.get('host', 'Unknown')} - {_time_text(review.get('created_at'))}", styles["small"]))
                story.append(_paragraph(review.get("note") or "No rationale recorded", styles["body"]))
        if history:
            story.append(Paragraph("Decision history and rationale", styles["subsection"]))
            labels = {"reviewed": "Reviewed", "needs_action": "Needs action", "monitor": "Monitor"}
            for review in history:
                origin = review.get("origin") or {}
                story.append(_paragraph(f"Review #{review.get('id')} - {origin.get('host', 'Unknown')} - {labels.get(review.get('status'), 'Unknown')} - {review.get('reviewer') or 'Former member'} - {_time_text(review.get('created_at'))}", styles["small"]))
                story.append(_paragraph(review.get("note") or "No rationale recorded", styles["body"]))
        if reviews.get("history_truncated"):
            story.append(_paragraph("Only the latest 100 decision-history entries are included; older entries remain in workspace history.", styles["small"]))
    _append_changes(story, check.get("changes") or [], styles)


def _append_run_line(story: list[Any], run: dict[str, Any], styles: dict[str, ParagraphStyle]) -> None:
    actor = run.get("actor") or "system"
    story.append(Spacer(1, 5))
    story.append(_paragraph(
        f"Run #{run.get('id')} · {run.get('status')} · completed {_time_text(run.get('completed_at'))} · initiated by {actor}",
        styles["small"],
    ))


def _append_changes(story: list[Any], changes: list[dict[str, Any]], styles: dict[str, ParagraphStyle]) -> None:
    if not changes:
        story.append(_paragraph("No changes were detected in this run.", styles["small"]))
        return
    story.append(Paragraph("Changes detected in this run", styles["subsection"]))
    rows = [[
        _paragraph("Field", styles["table_header"]),
        _paragraph("Previous value", styles["table_header"]),
        _paragraph("Current value", styles["table_header"]),
    ]]
    for change in changes[:100]:
        rows.append([
            _paragraph(_change_field_label(change.get("field_path")), styles["cell"]),
            _paragraph(change.get("previous_value"), styles["cell"]),
            _paragraph(change.get("current_value"), styles["cell"]),
        ])
    story.append(_table(rows, [1.7 * inch, 2.4 * inch, 2.4 * inch]))
    if len(changes) > 100:
        story.append(_paragraph("Only the first 100 detected differences are included.", styles["small"]))


def _overview_run(check: dict[str, Any]) -> tuple[str, str]:
    run = check.get("run") if isinstance(check, dict) else None
    if not isinstance(run, dict):
        attempt = check.get("latest_attempt") if isinstance(check, dict) else None
        if isinstance(attempt, dict):
            return "No saved result", f"Latest attempt: {attempt.get('status') or 'unknown'}"
        return "No saved result", "No run is available in this report."
    status = str(run.get("status") or "saved")
    status_label = {
        "completed": "Completed",
        "completed_with_warnings": "Completed with warnings",
        "failed": "Failed",
        "running": "In progress",
        "queued": "Queued",
        "queued": "Queued",
    }.get(status, status.replace("_", " ").title())
    details = f"Run #{run.get('id', 'unknown')} · {status_label}"
    if run.get("completed_at"):
        details += f" · {_time_text(run['completed_at'])}"
    return status_label, details


def _overview_tile(label: str, value: Any, detail: Any, width: float, styles: dict[str, ParagraphStyle]) -> Table:
    tile = Table([
        [_paragraph(label.upper(), styles["overview_label"])],
        [_paragraph(value, styles["overview_value"])],
        [_paragraph(detail, styles["overview_detail"])],
    ], colWidths=[width])
    tile.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), OLIVE_050),
        ("LINEBEFORE", (0, 0), (0, -1), 2.2, OLIVE_600),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
        ("TOPPADDING", (0, 1), (-1, 1), 0),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 2),
        ("TOPPADDING", (0, 2), (-1, 2), 0),
        ("BOTTOMPADDING", (0, 2), (-1, 2), 8),
    ]))
    return tile


def _posture_attention_items(checks: dict[str, Any], generated_at: Any) -> list[tuple[str, str]]:
    """The same verdict the dashboard status board shows: what needs attention."""
    items: list[tuple[str, str]] = []
    dns = checks.get("dns") or {}
    web = checks.get("web") or {}
    dns_run, web_run = dns.get("run") or {}, web.get("run") or {}
    dns_snapshot, web_snapshot = dns_run.get("snapshot") or {}, web_run.get("snapshot") or {}
    if not dns_run:
        items.append(("warn", "No DNS and email check has been recorded."))
    else:
        errors = dns_snapshot.get("resolver_errors") or {}
        if errors:
            items.append(("warn", "These DNS lookups failed and remain unknown: " + ", ".join(sorted(errors)) + "."))
        assessment = dns_snapshot.get("email_authentication_assessment")
        full = assessment if isinstance(assessment, dict) and isinstance(assessment.get("guidance"), list) \
            else analyze_email_auth(dns_snapshot.get("records"), errors)
        for item in full.get("guidance") or []:
            if isinstance(item, dict) and item.get("level") in {"action", "warn"}:
                items.append(("warn", f"{item.get('area')}: {item.get('text')}"))
    if not web_run:
        items.append(("warn", "No website check has been recorded."))
    else:
        status = web_snapshot.get("http_status")
        if type(status) is not int or not 200 <= status < 400:
            items.append(("bad", f"The website did not return a healthy response ({status if type(status) is int else 'no response'})."))
        if _tls_valid_at_collection(web_snapshot.get("tls") or {}, web_run) is False:
            items.append(("bad", "The TLS certificate was outside its validity dates when checked."))
        headers = web_snapshot.get("security_headers")
        absent = sum(not value for value in headers.values()) if isinstance(headers, dict) else 0
        if absent:
            items.append(("warn", f"{absent} selected browser security header(s) are absent."))
    return items


def _append_status_banner(story: list[Any], checks: dict[str, Any], generated_at: Any, styles: dict[str, ParagraphStyle], content_width: float) -> None:
    items = _posture_attention_items(checks, generated_at)
    story.append(Spacer(1, 8))
    bad = any(level == "bad" for level, _ in items)
    palette = (colors.HexColor("#f2d6cf") if bad else colors.HexColor("#f4e8c4") if items else OLIVE_100)
    headline = ("All checked items look good" if not items
                else f"{len(items)} thing{'s' if len(items) != 1 else ''} need{'s' if len(items) == 1 else ''} attention")
    box = Table([[Paragraph(f"<b>{escape(headline)}</b>", ParagraphStyle(name="StatusHeadline", parent=styles["body"], fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=OLIVE_950))]]
                + [[_paragraph(("• " if True else "") + text, styles["body"])] for _, text in items], colWidths=[content_width])
    box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), palette), ("BOX", (0, 0), (-1, -1), 0.6, LINE),
                             ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    story.append(box)
    story.append(Spacer(1, 6))


def _append_posture_overview(story: list[Any], checks: dict[str, Any], styles: dict[str, ParagraphStyle], content_width: float) -> None:
    dns = checks.get("dns") or {}
    web = checks.get("web") or {}
    active = checks.get("web-active") or {}
    dns_run = dns.get("run") or {}
    web_run = web.get("run") or {}
    active_run = active.get("run") or {}
    dns_snapshot = dns_run.get("snapshot") or {}
    web_snapshot = web_run.get("snapshot") or {}
    active_snapshot = active_run.get("snapshot") or {}

    dns_status, dns_detail = _overview_run(dns)
    resolver_errors = dns_snapshot.get("resolver_errors") or {}
    if resolver_errors:
        dns_detail += f" · {len(resolver_errors)} lookup error(s) remain unknown"

    http_status = web_snapshot.get("http_status")
    web_value = f"HTTPS {http_status}" if type(http_status) is int else "No HTTP result"
    tls = web_snapshot.get("tls") or {}
    tls_valid = _tls_valid_at_collection(tls, web_run)
    web_detail = "TLS certificate valid at collection" if tls_valid is True else (
        "TLS certificate outside validity dates at collection" if tls_valid is False
        else "TLS validity dates not confirmed"
    )
    web_status = str(web_run.get("status") or "no saved run").replace("_", " ").title()
    if web_run.get("id") is not None:
        web_detail += f" · run #{web_run['id']} {web_status}"
    elif web.get("latest_attempt"):
        web_detail += f" · latest attempt {web.get('latest_attempt', {}).get('status') or 'unknown'}"

    if active_run:
        probes = active_snapshot.get("probes") or []
        findings = active_snapshot.get("findings") or []
        coverage = "Complete coverage" if active_snapshot.get("coverage_complete") is True else "Partial or unknown coverage"
        active_value = f"{len(probes)} fixed probes · {len(findings)} signature observation(s)"
        active_detail = f"{coverage} · run #{active_run.get('id', 'unknown')}"
    else:
        active_value = "Not run"
        active_detail = "Optional bounded path checks are manual and may be unavailable."

    changes = sum(
        len(check.get("changes") or [])
        for check in checks.values()
        if isinstance(check, dict) and isinstance(check.get("changes") or [], list)
    )
    changes_detail = "Saved evidence differences, including lookup-state changes; not a security score."
    cards = [
        ("DNS and email", dns_status, dns_detail),
        ("Website health", web_value, web_detail),
        ("Bounded path checks", active_value, active_detail),
        ("Recorded differences", str(changes), changes_detail if changes else "No field differences were saved."),
    ]
    story.append(Paragraph("At-a-glance coverage", styles["section"]))
    card_width = (content_width - 10) / 2
    cells = [[
        _overview_tile(label, value, detail, card_width, styles)
        for label, value, detail in cards[row:row + 2]
    ] for row in (0, 2)]
    overview = Table(cells, colWidths=[card_width, card_width], hAlign="LEFT")
    overview.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(overview)
    story.append(_paragraph(
        "Coverage summary only. Daedalus does not calculate a combined security score; failed or unavailable observations are not treated as missing records or confirmed changes.",
        styles["small"],
    ))


def build_external_posture_pdf(report_snapshot: dict[str, Any]) -> bytes:
    """Render an immutable DNS and website snapshot as a themed PDF."""
    domain = _text(report_snapshot.get("domain") or "Workspace")
    generated_at = _time_text(
        report_snapshot.get("generated_at") or datetime.now(UTC).isoformat()
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="DaedalusEyebrow", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=8, leading=10, textColor=OLIVE_600, alignment=TA_LEFT, spaceAfter=7,
    ))
    styles.add(ParagraphStyle(
        name="DaedalusTitle", parent=styles["Title"], fontName="Times-Roman",
        fontSize=25, leading=29, textColor=OLIVE_950, alignment=TA_LEFT, spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="DaedalusSubtitle", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=14, textColor=MUTED, alignment=TA_LEFT, spaceAfter=16,
    ))
    styles.add(ParagraphStyle(
        name="DaedalusSection", parent=styles["Heading2"], fontName="Times-Roman",
        fontSize=17, leading=21, textColor=OLIVE_950, spaceBefore=18, spaceAfter=8,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="DaedalusSubsection", parent=styles["Heading3"], fontName="Helvetica-Bold",
        fontSize=10, leading=13, textColor=OLIVE_800, spaceBefore=11, spaceAfter=5,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="DaedalusBody", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=9, leading=13, textColor=INK, spaceAfter=6, splitLongWords=1,
    ))
    styles.add(ParagraphStyle(
        name="DaedalusCell", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=7.5, leading=10, textColor=INK, splitLongWords=1,
    ))
    styles.add(ParagraphStyle(
        name="DaedalusTableHeader", parent=styles["BodyText"], fontName="Helvetica-Bold",
        fontSize=7.5, leading=10, textColor=OLIVE_950, splitLongWords=1,
    ))
    styles.add(ParagraphStyle(
        name="DaedalusSmall", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=7.5, leading=10, textColor=MUTED, splitLongWords=1,
    ))
    styles.add(ParagraphStyle(
        name="DaedalusOverviewLabel", parent=styles["BodyText"], fontName="Helvetica-Bold",
        fontSize=7, leading=9, textColor=OLIVE_600, splitLongWords=1,
    ))
    styles.add(ParagraphStyle(
        name="DaedalusOverviewValue", parent=styles["BodyText"], fontName="Helvetica-Bold",
        fontSize=11, leading=14, textColor=OLIVE_950, splitLongWords=1,
    ))
    styles.add(ParagraphStyle(
        name="DaedalusOverviewDetail", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=7.2, leading=9, textColor=MUTED, splitLongWords=1,
    ))
    for alias, target in {
        "section": "DaedalusSection",
        "subsection": "DaedalusSubsection",
        "body": "DaedalusBody",
        "cell": "DaedalusCell",
        "table_header": "DaedalusTableHeader",
        "small": "DaedalusSmall",
        "overview_label": "DaedalusOverviewLabel",
        "overview_value": "DaedalusOverviewValue",
        "overview_detail": "DaedalusOverviewDetail",
    }.items():
        styles.add(ParagraphStyle(name=alias, parent=styles[target]))

    output = io.BytesIO()
    doc = SimpleDocTemplate(
        output,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.62 * inch,
        bottomMargin=0.62 * inch,
        title=f"Daedalus External Posture Report — {domain}",
        author="Daedalus · Cyber Security Pilot",
        subject="Saved DNS, email, and website health evidence",
    )
    story: list[Any] = [
        Paragraph("DAEDALUS · CYBER SECURITY PILOT", styles["DaedalusEyebrow"]),
        Paragraph("External posture report", styles["DaedalusTitle"]),
        _paragraph(domain, styles["DaedalusSubtitle"]),
        _paragraph(
            f"Generated {generated_at} · Requested by {report_snapshot.get('requested_by') or 'workspace member'}",
            styles["DaedalusSmall"],
        ),
        Spacer(1, 12),
        _paragraph(
            "This report captures saved DNS/email checks, passive HTTPS observations, and authorized website audit evidence when available, including fixed-path exposure checks and Nikto observations. Generating this PDF does not start scans or assess third-party services. Audit scope and coverage limits are recorded with each result.",
            styles["DaedalusBody"],
        ),
    ]
    story.append(_paragraph(
        "Record lookup failures are shown as unknown. An unavailable result should not be interpreted as a missing record.",
        styles["DaedalusSmall"],
    ))
    checks = report_snapshot.get("checks") or {}
    _append_status_banner(story, checks, generated_at, styles, doc.width)
    _append_posture_overview(story, checks, styles, doc.width)
    _append_dns(story, checks.get("dns") or {}, styles)
    _append_website(story, checks.get("web") or {}, styles)
    if "web-active" in checks:
        _append_active_website(story, checks.get("web-active") or {}, styles)
    nikto = checks.get("web-nikto") or {}
    if nikto.get("run") or nikto.get("latest_attempt"):
        story.append(PageBreak())
        story.append(Paragraph("Nikto website audit", styles["section"]))
        _append_latest_attempt(story, nikto, styles)
        run = nikto.get("run") or nikto.get("latest_attempt") or {}
        snapshot = run.get("snapshot") or {}
        run_time = run.get("completed_at") or run.get("started_at")
        time_label = "Completed" if run.get("completed_at") else ("Queued" if run.get("status") == "queued" else "Started")
        status_label = str(run.get("status") or "unknown").replace("_", " ")
        story.append(_paragraph(f"Run #{run.get('id')} · {status_label} · {time_label} {_time_text(run_time)}", styles["small"]))
        if run.get("collection_started_at"):
            story.append(_paragraph(f"Collection started {_time_text(run['collection_started_at'])}", styles["small"]))
        if run.get("status") == "queued":
            story.append(_paragraph("This audit was queued when the report snapshot was captured. Collection has not started and no assessment is available in this snapshot.", styles["body"]))
        if run.get("status") == "running":
            story.append(_paragraph("This audit was still running when the report snapshot was captured. Findings are not available in this snapshot; generate a new report after it finishes.", styles["body"]))
        story.append(_paragraph("Standard HTTPS tests excluding denial-of-service tests. Test exhaustion is not confirmed; missing findings do not prove resolution.", styles["body"]))
        if run.get("error_summary"):
            story.append(_paragraph(run["error_summary"], styles["body"]))
        findings = snapshot.get("findings") or []
        for finding in findings[:100]:
            observation = [_paragraph(f"Nikto test {finding.get('test_id')} · {finding.get('method')} {finding.get('path')}", styles["body"])]
            if finding.get("description"):
                observation.append(_paragraph(finding["description"], styles["small"]))
            story.append(KeepTogether(observation))
        if len(findings) > 100:
            story.append(_paragraph("Only the first 100 observations are included; the dashboard retains the complete saved set.", styles["small"]))
        if not findings and snapshot:
            story.append(_paragraph("No observations were retained in this run. Coverage remains unconfirmed.", styles["body"]))

    def draw_footer(canvas: Any, document: SimpleDocTemplate) -> None:
        canvas.saveState()
        width, _height = letter
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.45)
        canvas.line(document.leftMargin, 0.48 * inch, width - document.rightMargin, 0.48 * inch)
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(document.leftMargin, 0.32 * inch, f"Daedalus · {domain}")
        canvas.drawRightString(width - document.rightMargin, 0.32 * inch, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
    return output.getvalue()


def build_meraki_security_pdf(report_snapshot: dict[str, Any]) -> bytes:
    """Render a read-only Meraki inventory and security-configuration snapshot."""
    meraki = report_snapshot.get("meraki") or {}
    organization = meraki.get("organization") or {}
    organization_name = _text(organization.get("name") or report_snapshot.get("domain") or "Meraki organization")
    generated_at = meraki.get("collected_at") or report_snapshot.get("generated_at") or datetime.now(UTC).isoformat()
    summary = meraki.get("summary") or {}
    networks = meraki.get("networks") or []
    devices = meraki.get("devices") or []
    controls = meraki.get("security_controls") or []
    findings = meraki.get("findings") or []
    warnings = meraki.get("warnings") or []

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="MerakiEyebrow", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=8, leading=10, textColor=OLIVE_600, alignment=TA_LEFT, spaceAfter=7,
    ))
    styles.add(ParagraphStyle(
        name="MerakiTitle", parent=styles["Title"], fontName="Times-Roman",
        fontSize=25, leading=29, textColor=OLIVE_950, alignment=TA_LEFT, spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="MerakiSubtitle", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=14, textColor=MUTED, spaceAfter=13,
    ))
    styles.add(ParagraphStyle(
        name="MerakiSection", parent=styles["Heading2"], fontName="Times-Roman",
        fontSize=17, leading=21, textColor=OLIVE_950, spaceBefore=18, spaceAfter=8,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="MerakiSubsection", parent=styles["Heading3"], fontName="Helvetica-Bold",
        fontSize=10, leading=13, textColor=OLIVE_800, spaceBefore=11, spaceAfter=5,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="MerakiBody", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=9, leading=13, textColor=INK, spaceAfter=6, splitLongWords=1,
    ))
    styles.add(ParagraphStyle(
        name="MerakiCell", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=7.3, leading=9.5, textColor=INK, splitLongWords=1,
    ))
    styles.add(ParagraphStyle(
        name="MerakiTableHeader", parent=styles["BodyText"], fontName="Helvetica-Bold",
        fontSize=7.3, leading=9.5, textColor=OLIVE_950, splitLongWords=1,
    ))
    styles.add(ParagraphStyle(
        name="MerakiSmall", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=7.5, leading=10, textColor=MUTED, splitLongWords=1,
    ))

    output = io.BytesIO()
    doc = SimpleDocTemplate(
        output,
        pagesize=letter,
        rightMargin=0.58 * inch,
        leftMargin=0.58 * inch,
        topMargin=0.62 * inch,
        bottomMargin=0.62 * inch,
        title=f"Daedalus Meraki Security Report — {organization_name}",
        author="Daedalus · Cyber Security Pilot",
        subject="Read-only Meraki network inventory and security configuration snapshot",
    )
    created_by = report_snapshot.get("requested_by") or "workspace member"
    story: list[Any] = [
        Paragraph("DAEDALUS · CYBER SECURITY PILOT", styles["MerakiEyebrow"]),
        Paragraph("Meraki security report", styles["MerakiTitle"]),
        _paragraph(organization_name, styles["MerakiSubtitle"]),
        _paragraph(f"Snapshot {generated_at} · Requested by {created_by}", styles["MerakiSmall"]),
        Spacer(1, 10),
        _paragraph(
            "This report is a read-only snapshot of inventory and selected network security configuration returned by the Meraki Dashboard API. Daedalus does not change Meraki settings. Unsupported or unavailable controls are shown as coverage gaps, not as disabled controls.",
            styles["MerakiBody"],
        ),
    ]

    status_counts = summary.get("device_status_counts") or {}
    status_line = ", ".join(f"{name}: {count}" for name, count in sorted(status_counts.items())) or "No status data returned"
    summary_rows = [
        [_paragraph("Measure", styles["MerakiTableHeader"]), _paragraph("Observed", styles["MerakiTableHeader"])],
        [_paragraph("Networks", styles["MerakiCell"]), _paragraph(summary.get("network_count", len(networks)), styles["MerakiCell"])],
        [_paragraph("Assigned devices", styles["MerakiCell"]), _paragraph(summary.get("device_count", len(devices)), styles["MerakiCell"])],
        [_paragraph("Appliance networks", styles["MerakiCell"]), _paragraph(summary.get("appliance_network_count", 0), styles["MerakiCell"])],
        [_paragraph("Switch networks / devices", styles["MerakiCell"]), _paragraph(f"{summary.get('switch_network_count', 0)} / {summary.get('switch_device_count', 0)}", styles["MerakiCell"])],
        [_paragraph("Wireless networks", styles["MerakiCell"]), _paragraph(summary.get("wireless_network_count", 0), styles["MerakiCell"])],
        [_paragraph("Wireless RF profiles / assignments", styles["MerakiCell"]), _paragraph(f"{summary.get('rf_profile_count', 0)} / {summary.get('rf_assignments_collected', 0)}", styles["MerakiCell"])],
        [_paragraph("Licensing collection", styles["MerakiCell"]), _paragraph(summary.get("licensing_status") or "Not collected", styles["MerakiCell"])],
        [_paragraph("Managed topology networks", styles["MerakiCell"]), _paragraph(summary.get("topology_networks_collected", 0), styles["MerakiCell"])],
        [_paragraph("Aggregate client usage collection", styles["MerakiCell"]), _paragraph(summary.get("client_usage_status") or "Not collected", styles["MerakiCell"])],
        [_paragraph("Device availability", styles["MerakiCell"]), _paragraph(status_line, styles["MerakiCell"])],
        [_paragraph("Security controls read", styles["MerakiCell"]), _paragraph(summary.get("security_controls_collected", 0), styles["MerakiCell"])],
        [_paragraph("Controls unavailable", styles["MerakiCell"]), _paragraph(summary.get("security_controls_unavailable", 0), styles["MerakiCell"])],
    ]
    story.append(Paragraph("Organization summary", styles["MerakiSection"]))
    story.append(_table(summary_rows, [2.0 * inch, 4.9 * inch]))

    story.append(Paragraph("Networks", styles["MerakiSection"]))
    if networks:
        network_rows = [[
            _paragraph("Name", styles["MerakiTableHeader"]),
            _paragraph("Network ID", styles["MerakiTableHeader"]),
            _paragraph("Product types", styles["MerakiTableHeader"]),
            _paragraph("Tags", styles["MerakiTableHeader"]),
        ]]
        for network in networks:
            network_rows.append([
                _paragraph(network.get("name"), styles["MerakiCell"]),
                _paragraph(network.get("id"), styles["MerakiCell"]),
                _paragraph(network.get("productTypes") or [], styles["MerakiCell"]),
                _paragraph(network.get("tags") or [], styles["MerakiCell"]),
            ])
        story.append(_table(network_rows, [1.55 * inch, 1.65 * inch, 1.55 * inch, 2.15 * inch]))
    else:
        story.append(_paragraph("No network inventory was returned.", styles["MerakiBody"]))

    story.append(Paragraph("Device inventory and availability", styles["MerakiSection"]))
    if devices:
        device_rows = [[
            _paragraph("Device", styles["MerakiTableHeader"]),
            _paragraph("Model", styles["MerakiTableHeader"]),
            _paragraph("Product", styles["MerakiTableHeader"]),
            _paragraph("Network", styles["MerakiTableHeader"]),
            _paragraph("Status", styles["MerakiTableHeader"]),
            _paragraph("Last reported", styles["MerakiTableHeader"]),
        ]]
        for device in devices:
            device_rows.append([
                _paragraph(f"{device.get('name') or 'Unnamed'}\n{device.get('serial') or ''}", styles["MerakiCell"]),
                _paragraph(device.get("model"), styles["MerakiCell"]),
                _paragraph(device.get("productType"), styles["MerakiCell"]),
                _paragraph(device.get("networkId"), styles["MerakiCell"]),
                _paragraph(device.get("status") or "Unknown", styles["MerakiCell"]),
                _paragraph(device.get("lastReportedAt"), styles["MerakiCell"]),
            ])
        story.append(_table(device_rows, [1.45 * inch, 0.85 * inch, 0.8 * inch, 1.1 * inch, 0.75 * inch, 1.95 * inch]))
    else:
        story.append(_paragraph("No assigned device inventory was returned.", styles["MerakiBody"]))

    story.append(Paragraph("Configuration and observational coverage", styles["MerakiSection"]))
    if controls:
        if any(row.get("evidence_type") == "observation" for row in controls):
            story.append(_paragraph("Managed topology omits discovered devices and client identities. Client usage is an organization aggregate over the requested prior 24 hours; its changing traffic totals are excluded from configuration change alerts.", styles["MerakiBody"]))
        control_rows = [[
            _paragraph("Network", styles["MerakiTableHeader"]),
            _paragraph("Control", styles["MerakiTableHeader"]),
            _paragraph("Collection status", styles["MerakiTableHeader"]),
            _paragraph("Observed configuration", styles["MerakiTableHeader"]),
        ]]
        for control in controls:
            data = control.get("data")
            observed = data if data is not None else control.get("status", "Unavailable")
            if (control.get("control") == "WAN usage history" and isinstance(data, dict)
                    and type(control.get("pdf_evidence_summary_version")) is int
                    and control["pdf_evidence_summary_version"] == 1):
                observed = {key: data.get(key) for key in ("requested_timespan_seconds", "requested_resolution_seconds",
                    "interval_count", "interface_count", "first_interval_start", "last_interval_end")}
                observed["supporting_evidence"] = "See WAN usage history appendix; complete intervals remain in saved JSON evidence."
            if (control.get("control") == "Wireless client distributions" and isinstance(data, dict)
                    and type(control.get("pdf_evidence_summary_version")) is int
                    and control["pdf_evidence_summary_version"] == 1):
                observed = {key: data.get(key) for key in ("requested_timespan_seconds",
                    "wireless_client_count", "excluded_connection_count", "returned_record_count")}
                observed["supporting_evidence"] = "See wireless client analysis appendix; complete distributions remain in saved JSON."
            # Large arrays (switch ports, SSIDs, firewall rules) need separate
            # table rows. A single multi-page cell cannot be split by ReportLab.
            records = observed if isinstance(observed, list) else [observed]
            if isinstance(observed, dict) and any(isinstance(value, list) for value in observed.values()):
                scalar_fields = {key: value for key, value in observed.items() if not isinstance(value, list)}
                records = [scalar_fields] if scalar_fields else []
                for key, values in observed.items():
                    if isinstance(values, list):
                        records.extend({key: value} for value in values)
            records = records or ["No entries reported"]
            for record in records[:200]:
                rendered = _text(record)
                if len(rendered) > 1800 or len(rendered.splitlines()) > 24:
                    rendered = "\n".join(rendered[:1800].splitlines()[:24]) + " [continued in saved JSON]"
                control_rows.append([
                    _paragraph(control.get("network_name"), styles["MerakiCell"]),
                    _paragraph(control.get("control"), styles["MerakiCell"]),
                    _paragraph(control.get("status"), styles["MerakiCell"]),
                    _paragraph(rendered, styles["MerakiCell"]),
                ])
            if len(records) > 200:
                control_rows.append([_paragraph(control.get("network_name"), styles["MerakiCell"]),
                    _paragraph(control.get("control"), styles["MerakiCell"]),
                    _paragraph("Report excerpt", styles["MerakiCell"]),
                    _paragraph(f"{len(records) - 200} additional entries are retained in the saved JSON snapshot.", styles["MerakiCell"])])
        story.append(_table(control_rows, [1.25 * inch, 1.35 * inch, 1.05 * inch, 3.25 * inch]))
    else:
        story.append(_paragraph("No security configuration endpoints were applicable to the returned networks.", styles["MerakiBody"]))

    story.append(Paragraph("Review items", styles["MerakiSection"]))
    if findings:
        finding_rows = [[
            _paragraph("Status", styles["MerakiTableHeader"]),
            _paragraph("Observation", styles["MerakiTableHeader"]),
            _paragraph("Detail", styles["MerakiTableHeader"]),
        ]]
        for finding in findings:
            finding_rows.append([
                _paragraph(finding.get("status"), styles["MerakiCell"]),
                _paragraph(finding.get("title"), styles["MerakiCell"]),
                _paragraph(finding.get("detail"), styles["MerakiCell"]),
            ])
        story.append(_table(finding_rows, [1.1 * inch, 2.25 * inch, 3.55 * inch]))
    else:
        story.append(_paragraph("No review items were derived from the returned status and configuration fields.", styles["MerakiBody"]))

    if warnings:
        story.append(Paragraph("Collection warnings", styles["MerakiSection"]))
        for warning in warnings:
            story.append(_paragraph("• " + _text(warning), styles["MerakiSmall"]))

    comparison = report_snapshot.get("meraki_comparison")
    if isinstance(comparison, dict):
        story.append(Paragraph("Changes since the prior report", styles["MerakiSection"]))
        if comparison.get("baseline"):
            story.append(_paragraph("This report establishes the comparison baseline for this Cisco organization in this workspace.", styles["MerakiBody"]))
        else:
            story.append(_paragraph(f"Compared with saved report {comparison.get('previous_report_id')}: "
                                   f"{len(comparison.get('changes') or [])} control changes and "
                                   f"{len(comparison.get('coverage_changes') or [])} control coverage changes, "
                                   f"{len(comparison.get('inventory_changes') or [])} inventory changes and "
                                   f"{len(comparison.get('inventory_coverage_changes') or [])} inventory coverage changes. "
                                   "Unavailable controls are not reported as disabled protections. "
                                   "Complete before/after evidence is available in the dashboard's change download.", styles["MerakiBody"]))
            for change in (comparison.get("changes") or [])[:100]:
                story.append(_paragraph(f"{change.get('network_id')} / {change.get('device_serial') or 'network'}: {change.get('control')}", styles["MerakiBody"]))
            for change in (comparison.get("inventory_changes") or [])[:100]:
                fields = ", ".join(change.get("changed_fields") or [])
                story.append(_paragraph(f"{change.get('collection')} / {change.get('identifier')}: "
                                        f"{change.get('kind')}" + (f" ({fields})" if fields else ""), styles["MerakiBody"]))
            for change in (comparison.get("inventory_coverage_changes") or [])[:100]:
                story.append(_paragraph(f"{change.get('collection')} / {change.get('identifier') or 'collection'} "
                                        f"{change.get('field') or ''}: {change.get('previous_status')} to {change.get('current_status')}", styles["MerakiSmall"]))
            for change in (comparison.get("coverage_changes") or [])[:100]:
                story.append(_paragraph(f"{change.get('control')}: {change.get('previous_status')} to {change.get('current_status')}", styles["MerakiSmall"]))

    plan = report_snapshot.get("unifi_plan")
    if isinstance(plan, dict) and plan.get("schema_version") == 1:
        story.append(PageBreak())
        story.append(Paragraph("UniFi comparison and purchase planning", styles["MerakiSection"]))
        story.append(_paragraph(f"USD prices and availability observed {plan.get('price_observed_on')}. "
                                f"Inventory captured {plan.get('inventory_collected_at') or generated_at}.", styles["MerakiSmall"]))
        for note in plan.get("assumptions", []):
            story.append(_paragraph(note, styles["MerakiBody"]))

        def money(cents: int) -> str:
            return f"${cents / 100:,.2f}"

        for index, scenario in enumerate(plan.get("scenarios", [])):
            if index:
                story.append(PageBreak())
            story.append(_paragraph(scenario.get("name"), styles["MerakiSubsection"]))
            qualifier = "" if scenario.get("complete_inventory_pricing") else " - partial inventory pricing"
            story.append(_paragraph(f"Hardware subtotal: {money(scenario.get('hardware_subtotal_cents', 0))}{qualifier}", styles["MerakiBody"]))
            rows = [[_paragraph(label, styles["MerakiTableHeader"]) for label in
                     ("Meraki model / qty", "UniFi candidate", "Unit incl. surcharge", "Subtotal", "Availability observed")]]
            for row in scenario.get("rows", []):
                rows.append([_paragraph(f"{row.get('meraki_model')} / {row.get('quantity')}", styles["MerakiCell"]),
                             _paragraph(row.get("candidate_model"), styles["MerakiCell"]),
                             _paragraph(money(row.get("unit_with_surcharge_cents", 0)), styles["MerakiCell"]),
                             _paragraph(money(row.get("subtotal_cents", 0)), styles["MerakiCell"]),
                             _paragraph(row.get("availability_observed"), styles["MerakiCell"])])
            story.append(_table(rows, [1.3 * inch, 1.6 * inch, 1.15 * inch, 1.15 * inch, 1.7 * inch]))
            for row in scenario.get("rows", []):
                story.append(_paragraph(f"{row.get('meraki_model')} / {row.get('candidate_model')}: {row.get('review')}", styles["MerakiSmall"]))
                url = row.get("purchase_url") or ""
                # Only the fixed vendor origin and product slug are linkable.
                parsed = urlsplit(url)
                if (parsed.scheme == "https" and parsed.netloc == "store.ui.com"
                        and re.fullmatch(r"/us/en/products/[a-z0-9-]+", parsed.path)
                        and not parsed.query and not parsed.fragment):
                    story.append(Paragraph(f'<link href="{escape(url, quote=True)}" color="#464a34">'
                                           f'{escape(url)}</link>', styles["MerakiSmall"]))
            for row in scenario.get("unmatched", []):
                story.append(_paragraph(f"{row.get('quantity')} x {row.get('meraki_model')}: candidate and price need review.", styles["MerakiSmall"]))

    power = meraki.get("switch_power")
    if isinstance(power, list) and power:
        story.append(PageBreak())
        story.append(Paragraph("Switch PoE usage observations", styles["MerakiSection"]))
        story.append(_paragraph("Energy is measured over the requested prior 24 hours. Missing measurements remain unavailable. "
                                "The measured average is not peak demand and does not establish replacement switch PoE capacity.", styles["MerakiBody"]))
        rows = [[_paragraph(label, styles["MerakiTableHeader"]) for label in
                 ("Switch / network", "Collection / energy coverage", "Ports measured", "Energy / average")]]
        for item in power:
            data = item.get("data") if isinstance(item.get("data"), dict) else {}
            measured = data.get("measured_energy_wh")
            rows.append([_paragraph(f"{item.get('device_serial')} / {item.get('network_name')}", styles["MerakiCell"]),
                         _paragraph(f"{item.get('status')} / {data.get('energy_coverage') or 'unavailable'}", styles["MerakiCell"]),
                         _paragraph(f"{data.get('measured_port_count')} / {data.get('port_count')}" if data.get("port_count") is not None else "Unavailable", styles["MerakiCell"]),
                         _paragraph(f"{measured} Wh / {data.get('measured_average_watts')} W" if measured is not None else "Unavailable", styles["MerakiCell"])])
        story.append(_table(rows, [2.2 * inch, 1.8 * inch, 1 * inch, 1.9 * inch]))

    wireless = meraki.get("wireless_connections")
    if isinstance(wireless, list) and wireless:
        story.append(PageBreak())
        story.append(Paragraph("Wireless connection outcomes", styles["MerakiSection"]))
        story.append(_paragraph("Successful connection attempts and failure-stage counters cover the requested prior 24 hours. "
            "Missing devices and counters remain explicit. These observations are not a combined failure rate or security score, "
            "and are excluded from configuration change alerts.", styles["MerakiBody"]))
        for item in wireless:
            data = item.get("data") if isinstance(item.get("data"), dict) else {}
            story.append(_paragraph(f"{item.get('network_name')} - collection: {item.get('status')}; "
                f"counter coverage: {data.get('counter_coverage') or 'unavailable'}; "
                f"APs reporting: {data.get('reported_device_count', 'Unavailable')} / {data.get('expected_device_count', 'Unavailable')}", styles["MerakiBody"]))
            totals = data.get("observed_counter_totals") or {}
            rows = [[_paragraph("Observed counter", styles["MerakiTableHeader"]), _paragraph("Count", styles["MerakiTableHeader"])]]
            for key, title in (("success", "Successful connections"), ("assoc", "Association failures"),
                    ("auth", "Authentication failures"), ("dhcp", "DHCP failures"), ("dns", "DNS failures")):
                rows.append([_paragraph(title, styles["MerakiCell"]), _paragraph(totals.get(key, "Unavailable"), styles["MerakiCell"])])
            story.append(_table(rows, [4.5 * inch, 2.4 * inch]))

    channel = meraki.get("channel_utilization")
    if isinstance(channel, dict):
        story.append(PageBreak())
        story.append(Paragraph("Wireless channel utilization", styles["MerakiSection"]))
        story.append(_paragraph("Prior 24-hour per-band averages. Review prompts are total utilization at least 50% "
            "or non-Wi-Fi at least 20%. Missing measurements remain unavailable. These observations do not establish "
            "interference causes, peak load or replacement capacity.", styles["MerakiBody"]))
        data = channel.get("data") if isinstance(channel.get("data"), dict) else {}
        story.append(_paragraph(f"Collection: {channel.get('status')}; APs measured: "
            f"{data.get('reported_device_count', 'Unavailable')} / {data.get('expected_device_count', 'Unavailable')}; "
            f"bands meeting review threshold: {data.get('review_band_count', 'Unavailable')}", styles["MerakiBody"]))
        rows = [[_paragraph(title, styles["MerakiTableHeader"]) for title in
                 ("Access point", "GHz", "Wi-Fi", "Non-Wi-Fi", "Total", "Review")]]
        for row in data.get("rows", []):
            values = row.get("percentages") or {}
            cells = [row.get("device_serial"), row.get("band")]
            cells.extend(f"{values[key]:.2f}%" if key in values else "Unavailable" for key in ("wifi", "nonWifi", "total"))
            cells.append("Review" if row.get("review_threshold_met") else "No reported threshold met")
            rows.append([_paragraph(value, styles["MerakiCell"]) for value in cells])
        if len(rows) > 1:
            story.append(_table(rows, [1.5 * inch, .4 * inch, .9 * inch, 1 * inch, .9 * inch, 2.2 * inch]))

    wan = meraki.get("wan_uplinks")
    if isinstance(wan, dict):
        story.append(PageBreak())
        story.append(Paragraph("WAN / Internet uplinks", styles["MerakiSection"]))
        story.append(_paragraph("Current reported interface states. Circuit capacity and throughput are not measured. "
            "Ready or disconnected secondary interfaces do not establish an outage.", styles["MerakiBody"]))
        data = wan.get("data") if isinstance(wan.get("data"), dict) else {}
        story.append(_paragraph(f"Collection: {wan.get('status')}; assigned appliances reported: "
            f"{data.get('reported_device_count', 'Unavailable')} / {data.get('expected_device_count', 'Unavailable')}; "
            f"missing appliances: {data.get('missing_device_count', 'Unavailable')}", styles["MerakiBody"]))
        rows = [[_paragraph(title, styles["MerakiTableHeader"]) for title in
                 ("Appliance", "Network", "Interface", "Reported state", "Last reported")]]
        for row in data.get("rows", []):
            rows.append([_paragraph(value, styles["MerakiCell"]) for value in (
                row.get("device_name") or row.get("device_serial"), row.get("network_name") or row.get("network_id"),
                row.get("interface"), row.get("state"), row.get("last_reported_at"))])
        if len(rows) > 1:
            story.append(_table(rows, [1.4 * inch, 1.7 * inch, .7 * inch, 1.1 * inch, 2 * inch]))

    usage = meraki.get("wan_usage")
    if isinstance(usage, list) and usage:
        story.append(PageBreak())
        story.append(Paragraph("WAN usage history", styles["MerakiSection"]))
        story.append(_paragraph("Prior seven-day request at hourly resolution. Rates cover measured seconds only. "
            "Highest interval average is not an instantaneous peak or subscribed circuit capacity. Missing counters "
            "remain unavailable; complete full-window coverage is not inferred.", styles["MerakiBody"]))
        for observation in usage:
            data = observation.get("data") if isinstance(observation.get("data"), dict) else {}
            story.append(_paragraph(f"{observation.get('network_name', 'Network')} - collection: {observation.get('status')}; "
                f"intervals reported: {data.get('interval_count', 'Unavailable')}", styles["MerakiBody"]))
            story.append(_paragraph(f"Reported period: {data.get('first_interval_start') or 'Unavailable'} to "
                f"{data.get('last_interval_end') or 'Unavailable'}", styles["MerakiBody"]))
            rows = [[_paragraph(title, styles["MerakiTableHeader"]) for title in
                ("Interface", "Direction", "Observed GiB", "Measured hours", "Measured intervals", "Average Mbps", "Highest interval avg Mbps")]]
            for iface in data.get("interfaces", []):
                for field, label in (("sent", "Upload"), ("received", "Download")):
                    measured = iface.get("directions", {}).get(field, {})
                    def amount(key, scale=1):
                        value = measured.get(key)
                        return f"{value / scale:,.3f}" if type(value) in (int, float) and math.isfinite(value) and value >= 0 else "Unavailable"
                    count = measured.get("measured_interval_count")
                    interval_count = f"{count}/{iface.get('reported_interval_count')}" if type(count) is int else "Unavailable"
                    values = (iface.get("interface"), label, amount("observed_bytes", 1073741824), amount("observed_seconds", 3600),
                        interval_count, amount("average_mbps"), amount("peak_interval_average_mbps"))
                    rows.append([_paragraph(value, styles["MerakiCell"]) for value in values])
            if len(rows) > 1:
                story.append(_table(rows, [.7 * inch, .75 * inch, .9 * inch, .9 * inch, 1 * inch, .95 * inch, 1.7 * inch]))
            elif observation.get("status") == "complete":
                story.append(_paragraph("No interface counters reported. Usage remains unavailable.", styles["MerakiBody"]))

    switch_ports = meraki.get("switch_ports")
    if isinstance(switch_ports, list) and switch_ports:
        for observation in switch_ports:
            story.append(PageBreak())
            story.append(Paragraph("Switch health and port evidence", styles["MerakiSection"]))
            data = observation.get("data") if isinstance(observation.get("data"), dict) else {}
            story.append(_paragraph(f"{observation.get('device_name') or observation.get('device_serial')} / {observation.get('network_name')}; "
                f"collection: {observation.get('status')}; configuration: {observation.get('configuration_status')}", styles["MerakiBody"]))
            story.append(_paragraph("Reported link state and prior 24-hour counters. Review prompts require investigation; "
                "averages do not establish a bottleneck, peak load or replacement capacity. Unknown fields remain unavailable. "
                "Client/neighbor identities and diagnostic message text are omitted.", styles["MerakiBody"]))
            story.append(_paragraph(f"Reported ports: {data.get('reported_port_count', 'Unavailable')}; connected: "
                f"{data.get('connected_port_count', 'Unavailable')}; review ports: {data.get('review_port_count', 'Unavailable')}; "
                f"configured ports missing status: {data.get('missing_status_port_count', 'Unavailable')}; "
                f"diagnostic coverage: {data.get('diagnostic_coverage_port_count', 'Unavailable')}", styles["MerakiBody"]))
            rows = [[_paragraph(title, styles["MerakiTableHeader"]) for title in
                ("Port", "State / speed", "Uplink", "Mode / VLAN", "Total Kbps", "Energy Wh", "Review prompts")]]
            def number(value):
                return f"{value:,.3f}" if type(value) in (int, float) and math.isfinite(value) and value >= 0 else "Unavailable"
            for row in data.get("rows", []):
                uplink = "Yes" if row.get("is_uplink") is True else "No" if row.get("is_uplink") is False else "Unknown"
                values = (row.get("port_id"), f"{row.get('state') or 'Unknown'} / {row.get('speed') or 'Unavailable'}", uplink,
                    f"{row.get('mode') or 'Unknown'} / {row.get('vlan') if row.get('vlan') is not None else 'Unavailable'}",
                    number((row.get("traffic_kbps") or {}).get("total")), number(row.get("power_usage_wh")),
                    "; ".join(row.get("review_prompts") or []) or "No captured review prompt")
                rows.append([_paragraph(value, styles["MerakiCell"]) for value in values])
            if len(rows) > 1:
                story.append(_table(rows, [.45 * inch, 1.15 * inch, .55 * inch, .8 * inch, .8 * inch, .8 * inch, 2.35 * inch]))
            elif observation.get("status") == "complete":
                story.append(_paragraph("No ports reported; port health remains unavailable.", styles["MerakiBody"]))

    refresh = plan.get("refresh_plan") if isinstance(plan, dict) else None
    if isinstance(refresh, dict) and refresh.get("schema_version") == 1 and refresh.get("currency") == "USD":
        story.append(PageBreak())
        story.append(Paragraph("Equipment refresh reserve", styles["MerakiSection"]))
        story.append(_paragraph(refresh.get("scope"), styles["MerakiBody"]))
        rows = [[_paragraph(title, styles["MerakiTableHeader"]) for title in
            ("Scenario", "Assumed cycle", "Equipment subtotal", "Annual reserve", "Inventory coverage")]]
        for row in refresh.get("scenarios", [])[:2]:
            def budget(value):
                return f"${value / 100:,.2f}" if type(value) is int and 0 <= value <= 10**15 else "Unavailable"
            values = (row.get("name"), f"{row.get('replacement_cycle_years')} years", budget(row.get("equipment_subtotal_cents")),
                budget(row.get("annual_reserve_cents")), "All assigned inventory priced" if row.get("complete_inventory_pricing") is True else
                f"Partial pricing; {row.get('unpriced_device_count', 'Unknown')} unpriced devices")
            rows.append([_paragraph(value, styles["MerakiCell"]) for value in values])
        story.append(_table(rows, [2.1 * inch, .9 * inch, 1.2 * inch, 1.1 * inch, 1.6 * inch]))

    if type(meraki.get("topology_detail_version")) is int and meraki["topology_detail_version"] == 1:
        from daedalus.meraki_topology import project_topology
        graph = project_topology(meraki, complete=True)
        if graph["networks"]:
            story.append(PageBreak())
            story.append(Paragraph("Observed network relationships", styles["MerakiSection"]))
            story.append(_paragraph(graph["scope"], styles["MerakiBody"]))
            for network in graph["networks"]:
                story.append(_paragraph(f"{network['network_name']} - collection: {network['status']}; assigned nodes: "
                    f"{network['node_count'] if network['node_count'] is not None else 'Unavailable'}; relationship pairs: "
                    f"{network['link_count'] if network['link_count'] is not None else 'Unavailable'}", styles["MerakiSubsection"]))
                if network["status"] != "complete": continue
                story.append(_paragraph(f"Nodes without observed links: {network['isolated_node_count']}; reported root flags: "
                    f"{network['root_node_count']}; collection omitted nodes: {network['omitted_node_count']}; "
                    f"collection omitted links: {network['omitted_link_count']}; API errors: {network['reported_error_count']}", styles["MerakiBody"]))
                for node in network["nodes"]:
                    story.append(_paragraph(f"{node['name']} / {node['model']}" + (" - API root flag" if node['reported_root'] is True else ""), styles["MerakiSmall"]))
                rows = [[_paragraph(title, styles["MerakiTableHeader"]) for title in ("Assigned device", "Observed neighbor", "Relationship count")]]
                for link in network["links"]:
                    rows.append([_paragraph(value, styles["MerakiCell"]) for value in (*link["endpoint_names"], link["link_count"])])
                if len(rows) > 1: story.append(_table(rows, [2.8 * inch, 2.8 * inch, 1.3 * inch]))
                else: story.append(_paragraph("No managed-device relationships reported. Missing links do not establish disconnection.", styles["MerakiBody"]))

    from daedalus.meraki_cis8 import project_cis8_assessment
    cis8 = project_cis8_assessment(report_snapshot.get("meraki_cis8"))
    if cis8 is not None:
        story.append(PageBreak())
        story.append(Paragraph("CIS Controls v8 evidence review", styles["MerakiSection"]))
        story.append(_paragraph(cis8["scope"], styles["MerakiBody"]))
        counts = cis8["summary"]
        story.append(_paragraph(f"Partial evidence: {counts['partial']}; review observations: {counts['review']}; "
            f"not assessed: {counts['not_assessed']}. All controls require human assessment.", styles["MerakiBody"]))
        labels = {"partial": "Partial evidence", "review": "Review observations", "not_assessed": "Not assessed"}
        for row in cis8["rows"]:
            section = [
                _paragraph(f"CIS {row['control_id']} - {row['title']}", styles["MerakiSubsection"]),
                _paragraph(f"Status: {labels[row['status']]}. {row['observation']}", styles["MerakiBody"]),
                _paragraph("Next review: " + row["next_action"], styles["MerakiBody"]),
                _paragraph("Saved evidence references: " + ("; ".join(row["evidence_references"]) or "No assessed Meraki evidence for this control"), styles["MerakiSmall"]),
            ]
            story.append(KeepTogether(section))
        story.append(Paragraph('<link href="https://www.cisecurity.org/controls/cis-controls-navigator/v8" color="#464a34">CIS Controls v8 reference</link>', styles["MerakiSmall"]))

    from daedalus.meraki_clients import project_wireless_clients
    wireless_clients = meraki.get("wireless_clients")
    if isinstance(wireless_clients, list) and wireless_clients:
        story.append(PageBreak())
        story.append(Paragraph("Wireless client analysis", styles["MerakiSection"]))
        for observation in wireless_clients[:500]:
            if not isinstance(observation, dict):
                continue
            story.append(_paragraph(observation.get("network_name") or "Network", styles["MerakiSubsection"]))
            data = project_wireless_clients(observation.get("data"), limit=50_000) if observation.get("status") == "complete" else None
            if data is None:
                story.append(_paragraph("Collection: " + str(observation.get("status") or "unknown") + "; client distributions unavailable.", styles["MerakiBody"]))
                continue
            story.append(_paragraph(data["scope"], styles["MerakiBody"]))
            story.append(_paragraph(f"Wireless records: {data['wireless_client_count']}; returned records: {data['returned_record_count']}; excluded non-explicit-Wireless records: {data['excluded_connection_count']}. RSSI: not provided.", styles["MerakiBody"]))
            for key, title in (("ssid", "SSID"), ("os", "OS / device-type prediction"), ("vlan", "VLAN"), ("status", "Reported status")):
                distribution = data["distributions"][key]
                story.append(_paragraph(title, styles["MerakiSubsection"]))
                if distribution["status"] != "complete":
                    story.append(_paragraph("Distribution evidence invalid or unavailable.", styles["MerakiBody"]))
                    continue
                rows = [[_paragraph("Group", styles["MerakiTableHeader"]), _paragraph("Wireless records", styles["MerakiTableHeader"])]]
                rows.extend([_paragraph(row["label"], styles["MerakiCell"]), str(row["count"])] for row in distribution["rows"])
                rows.append(["Missing/unsupported labels", str(distribution["unknown_count"])])
                story.append(_table(rows, [5.4 * inch, 1.5 * inch]))

    from daedalus.meraki_actions import project_action_plan
    action_plan = project_action_plan(report_snapshot.get("meraki_action_plan"))
    if action_plan is not None:
        story.append(PageBreak())
        story.append(Paragraph("Recommendations & implementation plan", styles["MerakiSection"]))
        story.append(_paragraph(action_plan["scope"], styles["MerakiBody"]))
        labels = {"review": "Review observation", "planning": "Design / planning review", "evidence_gap": "Evidence gap"}
        for phase, title in enumerate(action_plan["phases"]):
            story.append(_paragraph(title, styles["MerakiSubsection"]))
            rows = [row for row in action_plan["rows"] if row["phase"] == phase]
            if not rows:
                story.append(_paragraph("No actions derived for this window; this does not certify a healthy network.", styles["MerakiBody"]))
            for row in rows:
                story.append(KeepTogether([
                    _paragraph(row["title"] + " - " + labels[row["status"]], styles["MerakiSubsection"]),
                    _paragraph("Observation: " + row["observation"], styles["MerakiBody"]),
                    _paragraph("Suggested owner: " + row["suggested_owner"], styles["MerakiSmall"]),
                    _paragraph("Next action: " + row["action"], styles["MerakiBody"]),
                    _paragraph("Validation: " + row["verification"], styles["MerakiBody"]),
                    _paragraph("Saved evidence references: " + "; ".join(row["evidence_references"]), styles["MerakiSmall"]),
                ]))

    if type(meraki.get("topology_diagram_version")) is int and meraki["topology_diagram_version"] == 1:
        from daedalus.meraki_topology import project_topology
        from reportlab.graphics.shapes import Drawing, Line, Rect, String
        graph = project_topology(meraki)
        for network in graph["networks"]:
            diagram = network.get("diagram")
            if not diagram or diagram.get("status") != "available":
                continue
            from daedalus.meraki_diagram import diagram_sheets
            for sheet in diagram_sheets(diagram):
                story.append(PageBreak())
                story.append(Paragraph("Network diagram", styles["MerakiSection"]))
                story.append(_paragraph(f"{network['network_name']} - diagram sheet {sheet['sheet']}/{sheet['sheet_count']}", styles["MerakiSubsection"]))
                story.append(_paragraph(diagram["scope"], styles["MerakiBody"]))
                drawing = Drawing(sheet["width"], sheet["height"])
                by_id = {node["device_serial"]: node for node in sheet["nodes"]}
                for link in sheet["links"]:
                    a, b = (by_id[key] for key in link["device_serials"])
                    drawing.add(Line(a["x"] + 90, sheet["height"] - a["y"] - 35,
                        b["x"] + 90, sheet["height"] - b["y"] - 35, strokeColor=OLIVE_600, strokeWidth=2))
                for node in sheet["nodes"]:
                    y = sheet["height"] - node["y"] - node["height"]
                    drawing.add(Rect(node["x"], y, node["width"], node["height"], rx=8, ry=8,
                        fillColor=OLIVE_800 if node["reported_root"] is True else OLIVE_050, strokeColor=OLIVE_600))
                    drawing.add(String(node["x"] + 90, y + 26, "#" + str(node["number"]),
                        fontName="Helvetica-Bold", fontSize=26, textAnchor="middle",
                        fillColor=OLIVE_050 if node["reported_root"] is True else INK))
                scale = 6.9 * inch / sheet["width"]
                drawing.scale(scale, scale); drawing.width *= scale; drawing.height *= scale
                story.append(drawing)
                story.append(_paragraph(f"Full diagram preview: {len(diagram['nodes'])} assigned devices, {len(diagram['links'])} relationship pairs; {diagram['additional_nodes']} additional devices and {diagram['additional_links']} additional pairs outside preview. Complete evidence remains in saved JSON.", styles["MerakiSmall"]))
                if sheet["cross_sheet_links"]:
                    story.append(_paragraph("Relationships continuing on other diagram sheets", styles["MerakiSubsection"]))
                    for link in sheet["cross_sheet_links"]:
                        story.append(_paragraph(f"Device #{link['local_number']} / device #{link['other_number']} on sheet {link['other_sheet']}: {link['link_count']} reported relationship(s).", styles["MerakiSmall"]))
                rows = [[_paragraph(title, styles["MerakiTableHeader"]) for title in ("Key", "Assigned device", "Model / root observation")]]
                for node in sorted(sheet["nodes"], key=lambda row: row["number"]):
                    rows.append([str(node["number"]), _paragraph(node["name"], styles["MerakiCell"]),
                        _paragraph(node["model"] + (" / API root flag" if node["reported_root"] is True else ""), styles["MerakiCell"])])
                story.append(_table(rows, [.5 * inch, 4.4 * inch, 2 * inch]))
        if graph["additional_networks"]:
            story.append(_paragraph(f"{graph['additional_networks']} additional networks are outside the diagram preview. Complete captured relationships remain in the saved JSON and preceding relationship tables.", styles["MerakiSmall"]))

    def draw_footer(canvas: Any, document: SimpleDocTemplate) -> None:
        canvas.saveState()
        width, _height = letter
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.45)
        canvas.line(document.leftMargin, 0.48 * inch, width - document.rightMargin, 0.48 * inch)
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(document.leftMargin, 0.32 * inch, f"Daedalus · {organization_name}")
        canvas.drawRightString(width - document.rightMargin, 0.32 * inch, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
    return output.getvalue()


def build_cis_endpoint_pdf(report_snapshot: dict[str, Any]) -> bytes:
    """Render a normalized CSP endpoint compliance snapshot."""
    cis = report_snapshot.get("cis") or {}
    device_name = _text(cis.get("device_name") or "CIS endpoint")
    organization_name = _text(report_snapshot.get("organization_name") or report_snapshot.get("domain") or "Workspace")
    collected_at = _text(cis.get("collected_at") or report_snapshot.get("generated_at") or datetime.now(UTC).isoformat())
    requested_by = _text(report_snapshot.get("requested_by") or "workspace member")
    summary = cis.get("summary") or {}
    results = cis.get("results") or []
    changes = cis.get("changes") or []
    benchmark = cis.get("benchmark") or {}

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CISReportEyebrow", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=8, leading=10, textColor=OLIVE_600, alignment=TA_LEFT, spaceAfter=7,
    ))
    styles.add(ParagraphStyle(
        name="CISReportTitle", parent=styles["Title"], fontName="Times-Roman",
        fontSize=25, leading=29, textColor=OLIVE_950, alignment=TA_LEFT, spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="CISReportSubtitle", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=14, textColor=MUTED, spaceAfter=10,
    ))
    styles.add(ParagraphStyle(
        name="CISReportSection", parent=styles["Heading2"], fontName="Times-Roman",
        fontSize=17, leading=21, textColor=OLIVE_950, spaceBefore=17, spaceAfter=8,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="CISReportBody", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=9, leading=13, textColor=INK, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="CISReportCell", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=7.2, leading=9.2, textColor=INK, splitLongWords=1,
    ))
    styles.add(ParagraphStyle(
        name="CISReportHeader", parent=styles["BodyText"], fontName="Helvetica-Bold",
        fontSize=7.2, leading=9.2, textColor=OLIVE_950, splitLongWords=1,
    ))
    styles.add(ParagraphStyle(
        name="CISReportSmall", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=7.5, leading=10, textColor=MUTED, splitLongWords=1,
    ))

    output = io.BytesIO()
    doc = SimpleDocTemplate(
        output,
        pagesize=letter,
        rightMargin=0.58 * inch,
        leftMargin=0.58 * inch,
        topMargin=0.62 * inch,
        bottomMargin=0.62 * inch,
        title=f"Daedalus CIS Endpoint Report — {device_name}",
        author="Daedalus · Cyber Security Pilot",
        subject="Normalized CIS endpoint compliance snapshot",
    )
    profile_label = " · ".join(
        str(value) for value in (
            cis.get("profile_name"),
            cis.get("profile_version"),
            f"Level {benchmark.get('level')}" if benchmark.get("level") else None,
        ) if value
    ) or "Profile version not reported by the client"
    story: list[Any] = [
        Paragraph("DAEDALUS · CYBER SECURITY PILOT", styles["CISReportEyebrow"]),
        Paragraph("CIS endpoint report", styles["CISReportTitle"]),
        _paragraph(organization_name, styles["CISReportSubtitle"]),
        _paragraph(
            f"Endpoint {device_name} · {cis.get('platform') or 'Platform not reported'} · "
            f"{cis.get('os_version') or 'OS version not reported'}",
            styles["CISReportBody"],
        ),
        _paragraph(f"Collected {collected_at} · Requested by {requested_by}", styles["CISReportSmall"]),
        _paragraph(f"Profile: {profile_label}", styles["CISReportSmall"]),
        Spacer(1, 10),
        _paragraph(
            "This is a point-in-time snapshot of the checks submitted by the enrolled CSP endpoint. "
            "The pass rate includes manual and error results in its denominator. These results remain unassessed; the pass rate is not a CIS attestation. Daedalus does not retain "
            "the device serial number, IP address list, or full system inventory.",
            styles["CISReportBody"],
        ),
        Paragraph("Assessment summary", styles["CISReportSection"]),
    ]
    if benchmark:
        source_note = " ".join(
            str(value) for value in (
                benchmark.get("attribution"),
                f"License: {benchmark.get('license')}" if benchmark.get("license") else None,
                benchmark.get("disclaimer"),
            ) if value
        )
        if source_note:
            story.insert(6, _paragraph(source_note, styles["CISReportSmall"]))

    category_summary = summary.get("categories") or {}
    summary_rows = [[
        _paragraph("Measure", styles["CISReportHeader"]),
        _paragraph("Observed", styles["CISReportHeader"]),
    ]]
    def reported_count(values: dict[str, Any], key: str) -> str:
        value = values.get(key)
        return str(value) if type(value) is int and value >= 0 else "Not reported"

    passed, failed, total = (summary.get(key) for key in ("pass", "fail", "total"))
    coverage = f"{passed + failed}/{total} checks have pass or fail results" if all(type(value) is int and value >= 0 for value in (passed, failed, total)) and passed + failed <= total else "Not reported"
    score = summary.get("score")
    score_label = f"{score}%" if type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 100 else "Not reported"
    for label, value in (
        ("Pass rate", score_label),
        ("Assessment coverage", coverage),
        ("Total checks", reported_count(summary, "total")),
        ("Passed", reported_count(summary, "pass")),
        ("Failed", reported_count(summary, "fail")),
        ("Manual review", reported_count(summary, "manual")),
        ("Errors", reported_count(summary, "error")),
    ):
        summary_rows.append([
            _paragraph(label, styles["CISReportCell"]),
            _paragraph(value, styles["CISReportCell"]),
        ])
    for category, values in sorted(category_summary.items()):
        if isinstance(values, dict):
            category_label = {'macos': 'macOS', 'chrome': 'Chrome', 'safari': 'Safari'}.get(category, category.title())
            summary_rows.append([
                _paragraph(f"{category_label} checks", styles["CISReportCell"]),
                _paragraph(
                    f"{reported_count(values, 'pass')} pass · {reported_count(values, 'fail')} fail · "
                    f"{reported_count(values, 'manual')} manual · {reported_count(values, 'error')} error",
                    styles["CISReportCell"],
                ),
            ])
    story.append(_table(summary_rows, [2.2 * inch, 4.7 * inch]))

    story.append(Paragraph("Check results", styles["CISReportSection"]))
    if results:
        result_rows = [[
            _paragraph("Check", styles["CISReportHeader"]),
            _paragraph("Area", styles["CISReportHeader"]),
            _paragraph("CIS ID", styles["CISReportHeader"]),
            _paragraph("Status", styles["CISReportHeader"]),
            _paragraph("Description", styles["CISReportHeader"]),
            _paragraph("Evidence", styles["CISReportHeader"]),
        ]]
        for result in results:
            result_rows.append([
                _paragraph(result.get("id"), styles["CISReportCell"]),
                _paragraph(result.get("category"), styles["CISReportCell"]),
                _paragraph(", ".join(result.get("benchmark_ids") or []) or "—", styles["CISReportCell"]),
                _paragraph(result.get("status"), styles["CISReportCell"]),
                _paragraph(result.get("description"), styles["CISReportCell"]),
                _paragraph(result.get("details") or "No additional detail supplied.", styles["CISReportCell"]),
            ])
        story.append(_table(result_rows, [0.87 * inch, 0.55 * inch, 0.58 * inch, 0.58 * inch, 2.28 * inch, 2.34 * inch]))
    else:
        story.append(_paragraph("No normalized check results were saved.", styles["CISReportBody"]))

    story.append(Paragraph("Changes since the previous report", styles["CISReportSection"]))
    if changes:
        change_rows = [[
            _paragraph("Check", styles["CISReportHeader"]),
            _paragraph("Previous", styles["CISReportHeader"]),
            _paragraph("Current", styles["CISReportHeader"]),
            _paragraph("Detected", styles["CISReportHeader"]),
        ]]
        for change in changes:
            change_rows.append([
                _paragraph(change.get("check_id"), styles["CISReportCell"]),
                _paragraph(change.get("previous_status"), styles["CISReportCell"]),
                _paragraph(change.get("current_status"), styles["CISReportCell"]),
                _paragraph(change.get("detected_at"), styles["CISReportCell"]),
            ])
        story.append(_table(change_rows, [1.5 * inch, 1.1 * inch, 1.1 * inch, 3.2 * inch]))
    else:
        story.append(_paragraph("No recorded check-status differences accompany this report. A first report or a report without comparable prior evidence does not establish that settings were unchanged.", styles["CISReportBody"]))

    def draw_footer(canvas: Any, document: SimpleDocTemplate) -> None:
        canvas.saveState()
        width, _height = letter
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.45)
        canvas.line(document.leftMargin, 0.48 * inch, width - document.rightMargin, 0.48 * inch)
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(document.leftMargin, 0.32 * inch, f"Daedalus · {organization_name}")
        canvas.drawRightString(width - document.rightMargin, 0.32 * inch, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
    return output.getvalue()


def scanner_result_hosts(payload: Any) -> list[dict[str, Any]]:
    """Accept NmapUI's live list and historical {hosts: [...]} result shapes."""
    source = payload.get("hosts") if isinstance(payload, dict) else payload
    if not isinstance(source, list):
        raise ValueError("This scanner event does not contain a host result list.")
    if any(not isinstance(host, dict) for host in source):
        raise ValueError("Scanner host results must be objects.")
    return source


SCANNER_PHASE_LABELS = {
    "job_status": "Run status", "quick_scan_start": "Discovery started",
    "quickscan_results": "Discovery summary", "quick_scan_complete": "Discovery completed",
    "scan_feedback": "Scan progress", "scan_results": "Discovered hosts",
    "deep_scan_results": "Detailed scan results", "cve_array": "Reported vulnerability references",
    "deep_scan_host_complete": "Host scan completed", "deep_scan_complete": "Detailed scan completed",
}


def scanner_phase_label(event_name: str) -> str:
    return SCANNER_PHASE_LABELS.get(event_name, str(event_name).replace("_", " "))


def build_scanner_results_pdf(report_snapshot: dict[str, Any]) -> bytes:
    from daedalus.scanner_report_template import render_standardized_scanner_pdf
    return render_standardized_scanner_pdf(report_snapshot)
