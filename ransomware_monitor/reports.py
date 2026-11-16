from __future__ import annotations

from datetime import date
import html
from pathlib import Path
import time

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Font, PatternFill
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .monitor import (
    Event,
    MISSING,
    display_date,
    event_summary,
    has_value,
    intelligence_fields,
    text,
    tox_values,
)


REPORT_INK = colors.HexColor("#18353A")
REPORT_ACCENT = colors.HexColor("#087E75")
REPORT_MUTED = colors.HexColor("#5F7376")
REPORT_LINE = colors.HexColor("#D7E1DF")


def clear_event_reports(output_dir: Path, window_hours: float = 6) -> None:
    """Remove recent per-incident PDFs before refreshing; retain older archives and workbook."""
    output_dir.mkdir(parents=True, exist_ok=True)
    cutoff = time.time() - window_hours * 3600
    for report in output_dir.rglob("*.pdf"):
        if report.is_file() and report.stat().st_mtime >= cutoff:
            report.unlink()
    for child in sorted(output_dir.rglob("*"), key=lambda path: len(path.parts), reverse=True):
        if child.is_dir():
            try:
                child.rmdir()
            except OSError:
                pass


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportEyebrow",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=REPORT_ACCENT,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="IncidentTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=21,
        leading=26,
        alignment=0,
        textColor=REPORT_INK,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=REPORT_MUTED,
        spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        name="ReportSection",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=REPORT_INK,
        spaceBefore=13,
        spaceAfter=6,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="ReportBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=REPORT_INK,
        splitLongWords=True,
    ))
    styles.add(ParagraphStyle(
        name="ReportLabel",
        parent=styles["ReportBody"],
        fontName="Helvetica-Bold",
        textColor=REPORT_MUTED,
    ))
    styles.add(ParagraphStyle(
        name="SummaryPoint",
        parent=styles["ReportBody"],
        leftIndent=11,
        firstLineIndent=-9,
        spaceAfter=4,
    ))
    return styles


def _page_chrome(canvas, document) -> None:
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(REPORT_INK)
    canvas.rect(0, height - 7 * mm, width, 7 * mm, fill=1, stroke=0)
    canvas.setStrokeColor(REPORT_LINE)
    canvas.line(15 * mm, 12 * mm, width - 15 * mm, 12 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(REPORT_MUTED)
    canvas.drawString(15 * mm, 8 * mm, "RANSOMWARE.LIVE  |  TELECOM CTI  |  SOURCE-ATTRIBUTED DATA")
    canvas.drawRightString(width - 15 * mm, 8 * mm, f"{document.page}")
    canvas.restoreState()


def _paragraph(value, style) -> Paragraph:
    escaped = html.escape(text(value)).replace("\n", "<br/>")
    return Paragraph(escaped, style)


def _section_table(rows: list[tuple[str, object]], styles) -> Table:
    data = [[_paragraph(label, styles["ReportLabel"]), _paragraph(value, styles["ReportBody"])] for label, value in rows]
    table = Table(data, colWidths=[48 * mm, 132 * mm], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F4")),
        ("LINEBELOW", (0, 0), (-1, -1), 0.45, REPORT_LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def _incident_name(event: Event) -> str:
    if event.group_name == MISSING:
        return event.organization
    return f"{event.organization} - {event.group_name}"


def _safe_name(value: str, limit: int = 100) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)[:limit]


def write_pdf(event: Event, output_dir: Path) -> Path:
    discovered = event.discovered if event.discovered != MISSING else date.today().isoformat()
    day_dir = output_dir / discovered[:10]
    day_dir.mkdir(parents=True, exist_ok=True)
    incident_name = _incident_name(event)
    path = day_dir / f"{_safe_name(incident_name, 125)}.pdf"
    styles = _styles()
    story = [
        Spacer(1, 3 * mm),
        Paragraph("TELECOM THREAT INTELLIGENCE  /  INCIDENT REPORT", styles["ReportEyebrow"]),
        Paragraph(html.escape(incident_name), styles["IncidentTitle"]),
        Paragraph(
            f"Discovered {html.escape(display_date(event.discovered))}  |  Source: ransomware.live",
            styles["ReportSubtitle"],
        ),
        Paragraph("Incident summary", styles["ReportSection"]),
    ]
    points = event_summary(event)
    if points:
        story.extend(Paragraph(f"- {html.escape(point)}", styles["SummaryPoint"]) for point in points)
    else:
        story.append(_paragraph(MISSING, styles["ReportBody"]))

    story.extend([
        Paragraph("Incident details", styles["ReportSection"]),
        _section_table([
            ("Affected organization", event.organization),
            ("Threat actor", event.group_name),
            ("Discover date", display_date(event.discovered)),
            ("Attack date", display_date(event.victim.get("attackdate") or event.source.get("attackdate"))),
        ], styles),
        Paragraph("Threat actor intelligence", styles["ReportSection"]),
        _section_table([(label, value) for label, value in intelligence_fields(event) if label != "IOCs"], styles),
    ])

    communication_rows = [
        ("ToX identifiers", tox_values(event.extras.get("iocs"))),
        ("Negotiation channel", event.extras.get("negotiations")),
        ("Verified onion / leak links", event.extras.get("working_links")),
    ]
    story.extend([
        Paragraph("Communication channels", styles["ReportSection"]),
        _section_table(communication_rows, styles),
        Paragraph("Indicators of compromise", styles["ReportSection"]),
        _section_table([("IOCs", next(value for label, value in intelligence_fields(event) if label == "IOCs"))], styles),
        Paragraph("Source article", styles["ReportSection"]),
    ])
    if event.article_url.startswith(("http://", "https://")):
        safe_url = html.escape(event.article_url, quote=True)
        story.append(Paragraph(f'<link href="{safe_url}" color="#087E75">{html.escape(event.article_url)}</link>', styles["ReportBody"]))
    else:
        story.append(_paragraph(event.article_url, styles["ReportBody"]))

    SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=incident_name,
        author="ransomware.live telecom CTI monitor",
    ).build(story, onFirstPage=_page_chrome, onLaterPages=_page_chrome)
    return path


def append_excel(event: Event, output_dir: Path) -> Path:
    path = output_dir / "master_events.xlsx"
    output_dir.mkdir(parents=True, exist_ok=True)
    headers = ["Event ID", "Organization", "Threat actor", "Discover date", "Attack date", "Sector", "Source article", "PDF report"]
    if path.exists():
        workbook = load_workbook(path)
        sheet = workbook.active
        sheet.cell(1, 2).value = "Organization"
        sheet.cell(1, 3).value = "Threat actor"
    else:
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Telecom incidents"
        sheet.append(headers)
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="18353A")
    pdf_path = write_pdf(event, output_dir)
    row = [
        event.event_id, event.organization, event.group_name, display_date(event.discovered),
        display_date(event.victim.get("attackdate") or event.source.get("attackdate")),
        text(event.victim.get("activity") or event.victim.get("sector") or event.source.get("activity")),
        event.article_url, str(pdf_path),
    ]
    existing_row = next(
        (row_number for row_number in range(2, sheet.max_row + 1) if sheet.cell(row_number, 1).value == event.event_id),
        None,
    )
    if existing_row is None:
        sheet.append(row)
    else:
        for column_number, value in enumerate(row, start=1):
            sheet.cell(existing_row, column_number).value = value
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    sheet.row_dimensions[1].height = 28
    from openpyxl.styles import Alignment
    for row_cells in sheet.iter_rows():
        for cell in row_cells:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
    for column in sheet.columns:
        sheet.column_dimensions[column[0].column_letter].width = min(max(len(str(column[0].value or "")) + 2, 14), 45)
    workbook.save(path)
    return pdf_path
