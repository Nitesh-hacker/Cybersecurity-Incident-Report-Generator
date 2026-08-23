"""
report_generator.py
Turns validated incident data into a standardized report, in Markdown
(for easy diffing/version control/emailing) and PDF (for distribution).

This module never touches raw/untrusted input directly -- callers are
expected to run data through security.validate_incident_data() first.
"""

from datetime import datetime
from io import BytesIO

from models import IncidentReport, TimelineEvent
from security import compute_integrity_hash, audit_log

MD_TEMPLATE = """# Incident Report: {title}

| Field | Value |
|---|---|
| Incident ID | {incident_id} |
| Severity | {severity} |
| Status | {status} |
| Classification | {classification} |
| Reported By | {reported_by} |
| Report Author | {report_author} |
| Date Reported | {date_reported} |
| Date Occurred | {date_occurred} |
| Generated At (UTC) | {generated_at} |

## Affected Systems
{affected_systems}

## Description
{description}

## Timeline
{timeline_section}

## Indicators of Compromise (IOCs)
{ioc_section}

## Impact Assessment
{impact_assessment}

## Containment Actions
{containment_actions}

## Eradication Actions
{eradication_actions}

## Recovery Actions
{recovery_actions}

## Root Cause
{root_cause}

## Recommendations
{recommendations}

---
Report Integrity Hash (SHA-256): `{integrity_hash}`
"""


def build_report(cleaned_data: dict) -> IncidentReport:
    """Build an IncidentReport object from already-validated/sanitized data."""
    timeline = [TimelineEvent(**e) for e in cleaned_data.get("timeline", [])]
    report = IncidentReport(
        incident_id=cleaned_data["incident_id"],
        title=cleaned_data["title"],
        severity=cleaned_data["severity"],
        status=cleaned_data["status"],
        classification=cleaned_data["classification"],
        reported_by=cleaned_data["reported_by"],
        report_author=cleaned_data["report_author"],
        date_reported=cleaned_data["date_reported"],
        date_occurred=cleaned_data["date_occurred"],
        affected_systems=cleaned_data["affected_systems"],
        description=cleaned_data["description"],
        timeline=timeline,
        indicators_of_compromise=cleaned_data.get("indicators_of_compromise", []),
        impact_assessment=cleaned_data.get("impact_assessment", ""),
        containment_actions=cleaned_data.get("containment_actions", ""),
        eradication_actions=cleaned_data.get("eradication_actions", ""),
        recovery_actions=cleaned_data.get("recovery_actions", ""),
        root_cause=cleaned_data.get("root_cause", ""),
        recommendations=cleaned_data.get("recommendations", ""),
    )
    return report


def render_markdown(report: IncidentReport) -> str:
    """Render the report to Markdown, then append an integrity hash of
    the content itself (hash computed over the report *without* the
    hash line, obviously)."""
    timeline_section = "\n".join(
        f"- **{e.timestamp}** — {e.description}" for e in report.timeline
    ) or "_No timeline events recorded._"

    ioc_section = "\n".join(
        f"- `{ioc}`" for ioc in report.indicators_of_compromise
    ) or "_No IOCs recorded._"

    body = MD_TEMPLATE.format(
        title=report.title,
        incident_id=report.incident_id,
        severity=report.severity,
        status=report.status,
        classification=report.classification,
        reported_by=report.reported_by,
        report_author=report.report_author,
        date_reported=report.date_reported,
        date_occurred=report.date_occurred,
        generated_at=report.generated_at,
        affected_systems=report.affected_systems,
        description=report.description,
        timeline_section=timeline_section,
        ioc_section=ioc_section,
        impact_assessment=report.impact_assessment or "_Not provided._",
        containment_actions=report.containment_actions or "_Not provided._",
        eradication_actions=report.eradication_actions or "_Not provided._",
        recovery_actions=report.recovery_actions or "_Not provided._",
        root_cause=report.root_cause or "_Not provided._",
        recommendations=report.recommendations or "_Not provided._",
        integrity_hash="PENDING",
    )
    integrity_hash = compute_integrity_hash(body)
    body = body.replace("Report Integrity Hash (SHA-256): `PENDING`",
                         f"Report Integrity Hash (SHA-256): `{integrity_hash}`")

    audit_log("REPORT_GENERATED", incident_id=report.incident_id,
              severity=report.severity, format="markdown")
    return body, integrity_hash


def render_pdf(report: IncidentReport, markdown_text: str) -> bytes:
    """Render the report to PDF bytes using reportlab (pure-Python,
    no external system dependencies -- avoids the attack surface of
    shelling out to a converter binary)."""
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )
    from reportlab.lib import colors

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=LETTER,
                             leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                             topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], spaceAfter=10)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=12, spaceAfter=6)
    body_style = styles["BodyText"]
    mono = ParagraphStyle("Mono", parent=styles["BodyText"], fontName="Courier", fontSize=8)

    def esc(text):
        # reportlab Paragraph interprets a small XML-like markup, so we
        # escape user content again at render time (belt-and-suspenders
        # on top of the HTML-escaping already done in security.py).
        return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    elems = []
    elems.append(Paragraph(esc(f"Incident Report: {report.title}"), h1))

    meta_rows = [
        ["Incident ID", report.incident_id],
        ["Severity", report.severity],
        ["Status", report.status],
        ["Classification", report.classification],
        ["Reported By", report.reported_by],
        ["Report Author", report.report_author],
        ["Date Reported", report.date_reported],
        ["Date Occurred", report.date_occurred],
        ["Generated At (UTC)", report.generated_at],
    ]
    table = Table([[esc(a), esc(b)] for a, b in meta_rows], colWidths=[2 * inch, 4 * inch])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(table)
    elems.append(Spacer(1, 12))

    sections = [
        ("Affected Systems", report.affected_systems),
        ("Description", report.description),
    ]
    for title, content in sections:
        elems.append(Paragraph(title, h2))
        elems.append(Paragraph(esc(content) or "Not provided.", body_style))

    elems.append(Paragraph("Timeline", h2))
    if report.timeline:
        for e in report.timeline:
            elems.append(Paragraph(esc(f"{e.timestamp} — {e.description}"), body_style))
    else:
        elems.append(Paragraph("No timeline events recorded.", body_style))

    elems.append(Paragraph("Indicators of Compromise (IOCs)", h2))
    if report.indicators_of_compromise:
        for ioc in report.indicators_of_compromise:
            elems.append(Paragraph(esc(ioc), mono))
    else:
        elems.append(Paragraph("No IOCs recorded.", body_style))

    for title, content in [
        ("Impact Assessment", report.impact_assessment),
        ("Containment Actions", report.containment_actions),
        ("Eradication Actions", report.eradication_actions),
        ("Recovery Actions", report.recovery_actions),
        ("Root Cause", report.root_cause),
        ("Recommendations", report.recommendations),
    ]:
        elems.append(Paragraph(title, h2))
        elems.append(Paragraph(esc(content) or "Not provided.", body_style))

    integrity_hash = compute_integrity_hash(markdown_text)
    elems.append(Spacer(1, 16))
    elems.append(Paragraph(f"Report Integrity Hash (SHA-256): {integrity_hash}", mono))

    doc.build(elems)
    audit_log("REPORT_GENERATED", incident_id=report.incident_id,
              severity=report.severity, format="pdf")
    return buf.getvalue()
