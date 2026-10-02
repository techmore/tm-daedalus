from __future__ import annotations

import io
from datetime import UTC, datetime
from html import escape
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

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
    story.append(_paragraph(
        f"Latest attempt #{attempt.get('id')}: {status} · started {_time_text(attempt.get('started_at'))}. "
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
    story.append(Paragraph("Email authentication interpretation", styles["subsection"]))
    story.append(_paragraph(
        "This interprets the published DNS text only. Daedalus does not send or inspect email, recursively evaluate SPF dependencies, or verify actual SPF/DKIM alignment.",
        styles["small"],
    ))
    story.append(_table(rows, [1.0 * inch, 1.35 * inch, 4.15 * inch]))


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
    story.append(Paragraph("Bounded website exposure observations", styles["section"]))
    _append_latest_attempt(story, check, styles)
    run = check.get("run")
    if not run or not run.get("snapshot"):
        story.append(_paragraph("No saved bounded exposure-check evidence is available.", styles["body"]))
        return
    _append_run_line(story, run, styles)
    snapshot = run["snapshot"]
    baseline = snapshot.get("baseline") or {}
    summary = [
        [_paragraph("Coverage", styles["table_header"]), _paragraph("Observation", styles["table_header"])],
        [_paragraph("Fixed preset", styles["cell"]), _paragraph(snapshot.get("preset_version") or "Unknown", styles["cell"])],
        [_paragraph("Coverage complete", styles["cell"]), _paragraph("Yes" if snapshot.get("coverage_complete") is True else "No · findings cannot be resolved from this run", styles["cell"])],
        [_paragraph("Missing-page baseline", styles["cell"]), _paragraph(baseline.get("assessment") or "Unknown", styles["cell"])],
    ]
    story.append(_table(summary, [1.8 * inch, 4.7 * inch]))
    probe_rows = [[_paragraph(label, styles["table_header"]) for label in ("Path", "HTTP", "Assessment", "Status")]]
    for probe in snapshot.get("probes") or []:
        probe_rows.append([_paragraph(probe.get("path") or "Unknown", styles["cell"]), _paragraph(probe.get("http_status") if probe.get("http_status") is not None else "Unknown", styles["cell"]), _paragraph(probe.get("assessment") or "unassessed", styles["cell"]), _paragraph(probe.get("error_code") or "None", styles["cell"])])
    if len(probe_rows) > 1:
        story.append(_table(probe_rows, [2.2 * inch, .65 * inch, 2.0 * inch, 1.65 * inch]))
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
                _paragraph(resource.get("resource_types") or [], styles["cell"]),
                _paragraph((resource.get("scheme") or "unknown").upper(), styles["cell"]),
            ])
        story.append(_table(resource_rows, [1.45 * inch, 1.8 * inch, 2.35 * inch, 0.9 * inch]))
        if snapshot.get("external_resources_truncated"):
            story.append(_paragraph("The stored inventory was capped at 100 linked origins.", styles["small"]))
    if snapshot.get("page_html_truncated"):
        story.append(_paragraph("The page exceeded 256 KiB; resource inventory covers only the captured first 256 KiB.", styles["small"]))
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
            _paragraph(change.get("field_path"), styles["cell"]),
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
    web_detail = "TLS certificate valid" if tls.get("certificate_valid") is True else "TLS validity not confirmed"
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
    changes_detail = "Confirmed field differences in saved comparisons; not a security score."
    cards = [
        ("DNS and email", dns_status, dns_detail),
        ("Website health", web_value, web_detail),
        ("Bounded path checks", active_value, active_detail),
        ("Confirmed changes", str(changes), changes_detail if changes else "No confirmed field differences were saved."),
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
            "This report captures saved DNS/email checks, passive HTTPS observations, and authorized fixed-path website exposure checks when available. It does not run Nmap, crawl pages, fetch linked resources, or assess third-party services.",
            styles["DaedalusBody"],
        ),
    ]
    story.append(_paragraph(
        "Record lookup failures are shown as unknown. An unavailable result should not be interpreted as a missing record.",
        styles["DaedalusSmall"],
    ))
    checks = report_snapshot.get("checks") or {}
    _append_posture_overview(story, checks, styles, doc.width)
    _append_dns(story, checks.get("dns") or {}, styles)
    _append_website(story, checks.get("web") or {}, styles)
    if "web-active" in checks:
        _append_active_website(story, checks.get("web-active") or {}, styles)

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
            "The pass rate includes manual checks and is not a CIS attestation. Daedalus does not retain "
            "the device serial number, IP address list, or full system inventory.",
            styles["CISReportBody"],
        ),
        Paragraph("Compliance summary", styles["CISReportSection"]),
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
    for label, value in (
        ("Pass rate", f"{summary.get('score', 0)}%"),
        ("Total checks", summary.get("total", len(results))),
        ("Passed", summary.get("pass", 0)),
        ("Failed", summary.get("fail", 0)),
        ("Manual review", summary.get("manual", 0)),
        ("Errors", summary.get("error", 0)),
    ):
        summary_rows.append([
            _paragraph(label, styles["CISReportCell"]),
            _paragraph(value, styles["CISReportCell"]),
        ])
    for category, values in sorted(category_summary.items()):
        if isinstance(values, dict):
            summary_rows.append([
                _paragraph(f"{category.title()} checks", styles["CISReportCell"]),
                _paragraph(
                    f"{values.get('pass', 0)}/{values.get('total', 0)} passed · "
                    f"{values.get('score', 0)}%",
                    styles["CISReportCell"],
                ),
            ])
    story.append(_table(summary_rows, [2.2 * inch, 4.7 * inch]))

    story.append(Paragraph("Check results", styles["CISReportSection"]))
    if results:
        result_rows = [[
            _paragraph("Check", styles["CISReportHeader"]),
            _paragraph("Category", styles["CISReportHeader"]),
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
        story.append(_paragraph("No check status changes were detected since the previous report.", styles["CISReportBody"]))

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
    """Render saved NmapUI evidence without executing or enriching a scan."""
    scan = report_snapshot.get("scanner") or {}
    run_events = scan.get("events")
    grouped = isinstance(run_events, list)
    result_events = [event for event in run_events if event.get("event_name") in {"scan_results", "quickscan_results", "deep_scan_results"}] if grouped else [scan]
    hosts = []
    styles = getSampleStyleSheet()
    for name, parent, font, size, leading, color in [
        ("ScannerTitle", "Title", "Times-Roman", 25, 29, OLIVE_950),
        ("ScannerSection", "Heading2", "Times-Roman", 16, 20, OLIVE_950),
        ("ScannerBody", "BodyText", "Helvetica", 9, 13, INK),
        ("ScannerCell", "BodyText", "Helvetica", 8, 11, INK),
    ]:
        styles.add(ParagraphStyle(name=name, parent=styles[parent], fontName=font,
                                  fontSize=size, leading=leading, textColor=color,
                                  alignment=TA_LEFT, spaceAfter=7, splitLongWords=1))
    styles["ScannerSection"].keepWithNext = True
    def paragraph(value: Any, style: str = "ScannerBody", limit: int = 1800) -> Paragraph:
        text = _text(value)
        if len(text) > limit or len(text.splitlines()) > 24:
            text = "\n".join(text[:limit].splitlines()[:24]) + " [continued in saved JSON evidence]"
        return _paragraph(text, styles[style])
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=letter, rightMargin=.58 * inch,
                            leftMargin=.58 * inch, topMargin=.62 * inch, bottomMargin=.62 * inch,
                            title="Daedalus Internal Scanner Results", author="Cyber Security Pilot")
    story = [paragraph("CYBER SECURITY PILOT / DAEDALUS"),
             paragraph("Internal scanner results", "ScannerTitle"),
             paragraph(report_snapshot.get("organization_name") or report_snapshot.get("domain")),
             paragraph(f"Scanner: {scan.get('name') or scan.get('agent_id') or 'Not recorded'}"),
             Spacer(1, 8)]
    if grouped:
        run = scan.get("run") or {}
        story.extend([
            paragraph(f"Run: {scan.get('source_job_id')}"),
            paragraph(f"Saved status: {run.get('status', 'unknown')}"),
            paragraph(f"Collected: {_time_text(run.get('first_occurred_at'))} to {_time_text(run.get('last_occurred_at'))}"),
            paragraph("This report snapshots all saved events in this explicit scanner run at request time. Later arrivals are not included. Findings are scanner observations and are not independently verified."),
            paragraph("Saved phase history", "ScannerSection"),
        ])
        if run.get("group_metadata_conflict"):
            story.append(paragraph("Saved events contain conflicting or invalid run metadata. The run status is unconfirmed; individual phase observations are retained below."))
        story.append(paragraph(f"Saved events in this snapshot: {len(run_events)}. Requested: {_time_text(report_snapshot.get('generated_at'))}"))
        for event in run_events:
            payload = event.get("payload")
            status = payload.get("status") if isinstance(payload, dict) and event.get("event_name") == "job_status" else None
            story.append(paragraph(f"{_time_text(event.get('occurred_at'))} · Event {event.get('id')} · {scanner_phase_label(event.get('event_name'))}" + (f" · {status}" if status else "")))
        if not result_events:
            story.append(paragraph("No saved result events were present when this report was requested."))
    else:
        story.extend([
            paragraph(f"Collected: {_time_text(scan.get('occurred_at'))}"),
            paragraph(f"Event: {scan.get('event_id')} / {scan.get('event_name')}"),
            paragraph("This report uses one saved scanner result event. It does not merge later phases or independently verify vulnerability findings."),
        ])
    for result_event in result_events:
        payload = result_event.get("payload")
        if result_event.get("event_name") == "quickscan_results" and isinstance(payload, dict) and all(key in payload for key in ("total_ips", "hosts_up", "time_taken")):
            story.append(paragraph(f"Discovery summary · Event {result_event.get('id', scan.get('event_id'))}", "ScannerSection"))
            story.append(paragraph(f"Targets: {payload['total_ips']} · Hosts up: {payload['hosts_up']} · Duration: {payload['time_taken']} seconds"))
            story.append(paragraph("This phase reports summary counts; it does not contain host or port records."))
            continue
        hosts = scanner_result_hosts(payload)
        if grouped:
            story.append(paragraph(f"Result event {result_event.get('id')}: {scanner_phase_label(result_event.get('event_name'))}", "ScannerSection"))
        story.append(paragraph(f"Observed host records: {len(hosts)}. Up to 200 hosts and 50 structured port records per host are displayed for this event. Complete evidence remains in the saved JSON."))
        for index, host in enumerate(hosts[:200], 1):
            address = host.get("ip") or host.get("address") or "Address not reported"
            story.append(paragraph(f"{index}. {address}", "ScannerSection", 200))
            metadata = []
            for label, key in [("Hostname", "hostname"), ("Vendor", "vendor"), ("MAC", "mac"),
                               ("Status", "status"), ("Version", "version"), ("Service info", "service_info")]:
                if host.get(key):
                    metadata.append(f"{label}: {_text(host[key])}")
            if metadata:
                story.append(paragraph("\n".join(metadata), limit=1200))
            ports = host.get("ports")
            if isinstance(ports, list) and all(isinstance(port, dict) for port in ports):
                if ports:
                    rows = [[paragraph(value, "ScannerCell") for value in ["Port", "State", "Service / evidence"]]]
                    for port in ports[:50]:
                        port_number = port.get("port", port.get("portid", port.get("number")))
                        protocol = port.get("protocol") or "not reported"
                        service = {key: port[key] for key in ("service", "product", "version", "cves", "scripts") if port.get(key)}
                        rows.append([paragraph(f"{port_number}/{protocol}", "ScannerCell", 90),
                                     paragraph(port.get("state") or "Not reported", "ScannerCell", 90),
                                     paragraph(service or "Not reported", "ScannerCell", 900)])
                    story.append(_table(rows, [.85 * inch, .85 * inch, 5.64 * inch]))
                    if len(ports) > 50:
                        story.append(paragraph(f"{len(ports) - 50} additional port records are in the saved JSON."))
                else:
                    story.append(paragraph("No structured ports were reported in this event."))
            else:
                story.append(paragraph(host.get("open_ports") or "Structured port data was not reported."))
            if host.get("vulnerabilities") or host.get("cves"):
                story.append(paragraph("Reported vulnerability evidence", "ScannerSection"))
                story.append(paragraph(host.get("vulnerabilities") or host.get("cves"), limit=1800))
        if not hosts:
            story.append(paragraph("No hosts are present in this saved result event."))
        if len(hosts) > 200:
            story.append(paragraph(f"{len(hosts) - 200} additional host records remain in the saved JSON."))
    if grouped:
        detailed_service_info = set()
        for event in result_events:
            if event.get("event_name") != "deep_scan_results":
                continue
            for host in scanner_result_hosts(event.get("payload")):
                address = host.get("ip") or host.get("address")
                values = host.get("service_info")
                if isinstance(address, str) and isinstance(values, list):
                    detailed_service_info.update((address, _text(value)) for value in values if value)
        supplemental = []
        for event in run_events:
            event_name = event.get("event_name")
            payload = event.get("payload")
            if event_name not in {"cve_array", "service_info", "scan_error", "deep_scan_error", "report_error"} or not payload:
                continue
            if event_name == "service_info" and isinstance(payload, dict):
                identity = (payload.get("target"), _text(payload.get("line")))
                if identity in detailed_service_info:
                    continue
            if event_name == "cve_array":
                references = payload.get("cve_array") if isinstance(payload, dict) else payload
                if isinstance(references, list) and not references:
                    continue
            supplemental.append(event)
        if supplemental:
            story.append(paragraph("Additional scanner evidence", "ScannerSection"))
            story.append(paragraph("These references and errors are recorded scanner output. Vulnerability references do not independently establish that a host is vulnerable."))
        for event in supplemental:
            story.append(paragraph(f"Event {event.get('id')}: {scanner_phase_label(event.get('event_name'))}", "ScannerSection"))
            payload = event.get("payload")
            if isinstance(payload, list):
                for item in payload[:50]:
                    story.append(paragraph(item, limit=1800))
                if len(payload) > 50:
                    story.append(paragraph(f"{len(payload) - 50} additional entries remain in saved JSON evidence."))
            else:
                story.append(paragraph(payload, limit=3000))
    def footer(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(LINE)
        canvas.line(.58 * inch, .42 * inch, 7.92 * inch, .42 * inch)
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(.58 * inch, .27 * inch, "Cyber Security Pilot / Daedalus - saved scanner evidence")
        canvas.drawRightString(7.92 * inch, .27 * inch, str(document.page))
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
