"""Render frozen Google Admin assessments using the existing portal palette."""
from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer


def build_google_admin_pdf(snapshot: dict) -> bytes:
    from daedalus.reports import _paragraph, _time_text
    serif, sans = "Times-Roman", "Helvetica"
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="GoogleTitle", fontName=serif, fontSize=27, leading=31, textColor=colors.HexColor("#493e31"), spaceAfter=14))
    styles.add(ParagraphStyle(name="GoogleHeading", fontName=sans, fontSize=12, leading=16, textColor=colors.HexColor("#586144"), spaceBefore=10, spaceAfter=4))
    styles.add(ParagraphStyle(name="GoogleBody", fontName=sans, fontSize=9, leading=11.5, textColor=colors.HexColor("#493e31"), spaceAfter=3, splitLongWords=True))
    output = io.BytesIO()
    report = snapshot.get("google_admin") or {}
    summary = report.get("summary") or {}
    doc = SimpleDocTemplate(output, pagesize=letter, leftMargin=.65*inch, rightMargin=.65*inch, topMargin=.65*inch, bottomMargin=.65*inch,
        title="Google Admin security audit", author="Daedalus / Cyber Security Pilot")
    body = styles["GoogleBody"]
    story = [_paragraph("DAEDALUS / CYBER SECURITY PILOT", styles["GoogleHeading"]), _paragraph("Google Admin security audit", styles["GoogleTitle"]),
        _paragraph(snapshot.get("domain", "Workspace"), body), _paragraph("Collected " + _time_text(report.get("collected_at")), body),
        _paragraph("Read-only account and role evidence for the approved Google Workspace customer. Settings are not changed by this audit. Missing evidence remains unknown or requires manual review.", body),
        _paragraph(f"Definitive assessment coverage: {summary.get('definitive', 0)}/{summary.get('applicable', 10)} checks ({summary.get('coverage_percent', 0)}%). Observed pass rate among definitive checks: {str(summary['observed_pass_rate']) + '%' if summary.get('observed_pass_rate') is not None else 'Not available'}.", body),
        _paragraph(report.get("framework", "CIS Controls v8.1") + " / " + report.get("mapping_type", "CSP interpretation"), body),
        _paragraph(report.get("benchmark", "Workspace Benchmark version/profile pending review"), body),
        _paragraph("Scope and limitations", styles["GoogleHeading"]),
        _paragraph("Approved customer: " + str(report.get("binding", {}).get("customer_id", "Unknown")) + "; verified domains: " + ", ".join(report.get("binding", {}).get("domains", [])), body),
        _paragraph("The API criterion assesses active administrators' 2SV enrollment/enforcement only. It does not prove phishing-resistant factors, group-derived administrator coverage or effective policies for every OU/group. A pass is not a CIS compliance attestation.", body)]
    for check in report.get("checks", []):
        block = []
        block.extend([_paragraph(check["id"] + " / " + check["title"], styles["GoogleHeading"]), _paragraph("Status: " + check["status"].replace("_", " ") + "; method: " + {"api": "API evidence", "api_and_manual": "API and manual review", "manual": "Manual evidence"}.get(check.get("method"), "Manual evidence"), body)])
        for label, key in (("Observed", "observed"), ("Expected", "expected"), ("Reason", "rationale"), ("Control mapping", "cis_controls"), ("Validation", "validation"), ("Source", "source")):
            if check.get(key):
                block.append(_paragraph(label + ": " + str(check[key]), body))
        manual = report.get("manual_evidence", {}).get(check["id"])
        if manual:
            block.append(_paragraph("Manual evidence recorded " + manual["captured_at"] + "; review remains required.", body))
            for label, key in (("Policy scope", "policy_scope"), ("Manual observation", "observed"), ("Proposed target", "expected"), ("Change rationale", "rationale"), ("Evidence reference", "source_reference"), ("Suggested owner", "owner"), ("Validation method", "validation")):
                block.append(_paragraph(label + ": " + manual[key], body))
        block.append(Spacer(1, 3))
        story.append(KeepTogether(block))
    comparison = snapshot.get("google_admin_comparison") or {}
    comparison_block = [_paragraph("Comparison history", styles["GoogleHeading"])]
    if comparison.get("baseline"):
        description = "First saved assessment; no previous report is available for comparison."
    elif not comparison.get("comparable"):
        description = "Baseline or customer scope changed. Configuration comparison is withheld."
    else:
        description = f"Compared with report {comparison.get('previous_report_id')}: {len(comparison.get('configuration_changes', []))} account/role observations changed; {len(comparison.get('coverage_changes', []))} coverage changes. Missing observations are not confirmed removals when collection is incomplete."
    comparison_block.append(_paragraph(description, body))
    comparison_block.append(_paragraph("Review the saved JSON evidence for individual changes. Proposed setting changes require the domain administrator's review, implementation and verification.", body))
    story.append(KeepTogether(comparison_block))
    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont(sans, 8)
        canvas.setFillColor(colors.HexColor("#586144"))
        canvas.drawString(.65*inch, .35*inch, "Daedalus / Read-only Google Admin audit")
        canvas.drawRightString(7.85*inch, .35*inch, f"Page {document.page}")
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
