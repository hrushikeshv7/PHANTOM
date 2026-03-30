"""
PHANTØM — PDF Threat Report Generator
Generates professional SOC-style PDF reports for any analyzed IOC.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from io import BytesIO
from datetime import datetime


# ── Color Palette ─────────────────────────────────────────────
BG_DARK    = colors.HexColor('#080810')
PANEL      = colors.HexColor('#0d0d1a')
RED        = colors.HexColor('#FF2D2D')
ORANGE     = colors.HexColor('#FF6B00')
GOLD       = colors.HexColor('#FFD700')
GREEN      = colors.HexColor('#00FF88')
BLUE       = colors.HexColor('#00D4FF')
MUTED      = colors.HexColor('#4a4a6a')
TEXT       = colors.HexColor('#c8c8e8')
WHITE      = colors.white
BLACK      = colors.black

SEVERITY_COLORS = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   GOLD,
    "LOW":      GREEN,
}


def generate_pdf_report(record: dict, raw_data: dict = None) -> bytes:
    """
    Generate a professional PDF threat report.
    Returns bytes of the PDF file.
    """
    buffer = BytesIO()
    doc    = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm,
    )

    styles   = getSampleStyleSheet()
    elements = []

    sev_color = SEVERITY_COLORS.get(record.get("severity", "LOW"), GREEN)

    # ── Header ────────────────────────────────────────────────
    header_style = ParagraphStyle(
        'Header',
        fontSize=22,
        textColor=RED,
        fontName='Helvetica-Bold',
        alignment=TA_LEFT,
        spaceAfter=2*mm,
    )
    elements.append(Paragraph("PHANTØM", header_style))

    sub_style = ParagraphStyle(
        'Sub',
        fontSize=9,
        textColor=MUTED,
        fontName='Helvetica',
        spaceAfter=6*mm,
    )
    elements.append(Paragraph("THREAT INTELLIGENCE REPORT", sub_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=RED, spaceAfter=6*mm))

    # ── IOC Summary Table ─────────────────────────────────────
    title_style = ParagraphStyle(
        'Title',
        fontSize=11,
        textColor=BLUE,
        fontName='Helvetica-Bold',
        spaceAfter=3*mm,
    )
    elements.append(Paragraph("■ THREAT SUMMARY", title_style))

    summary_data = [
        ["IOC",           record.get("ioc", "Unknown")],
        ["TYPE",          record.get("ioc_type", "ip").upper()],
        ["THREAT SCORE",  f"{record.get('threat_score', 0)}/100"],
        ["SEVERITY",      record.get("severity", "LOW")],
        ["COUNTRY",       record.get("country", "Unknown")],
        ["ANALYZED AT",   str(record.get("created_at", datetime.now()))[:19]],
    ]

    table = Table(summary_data, colWidths=[50*mm, 120*mm])
    table.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (0, -1), PANEL),
        ('BACKGROUND',  (1, 0), (1, -1), colors.HexColor('#0a0a15')),
        ('TEXTCOLOR',   (0, 0), (0, -1), MUTED),
        ('TEXTCOLOR',   (1, 0), (1, -1), TEXT),
        ('FONTNAME',    (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE',    (0, 0), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [PANEL, colors.HexColor('#0a0a15')]),
        ('GRID',        (0, 0), (-1, -1), 0.5, colors.HexColor('#1a1a2e')),
        ('PADDING',     (0, 0), (-1, -1), 8),
        # Highlight score row
        ('TEXTCOLOR',   (1, 2), (1, 2), sev_color),
        ('FONTNAME',    (1, 2), (1, 2), 'Helvetica-Bold'),
        ('FONTSIZE',    (1, 2), (1, 2), 14),
        ('TEXTCOLOR',   (1, 3), (1, 3), sev_color),
        ('FONTNAME',    (1, 3), (1, 3), 'Helvetica-Bold'),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 6*mm))

    # ── Score Breakdown ───────────────────────────────────────
    elements.append(Paragraph("■ SCORE BREAKDOWN", title_style))

    raw = record.get("raw_scores", {})
    breakdown_data = [
        ["SOURCE",    "RAW SCORE", "WEIGHTED"],
        ["VirusTotal",   f"{raw.get('vt',0):.1f}",     f"{raw.get('vt',0)*0.35:.2f}"],
        ["AbuseIPDB",    f"{raw.get('abuse',0):.1f}",  f"{raw.get('abuse',0)*0.30:.2f}"],
        ["Shodan",       f"{raw.get('shodan',0):.1f}", f"{raw.get('shodan',0)*0.20:.2f}"],
        ["OTX",          f"{raw.get('otx',0):.1f}",   f"{raw.get('otx',0)*0.15:.2f}"],
        ["BASE SCORE",   "—",                           f"{raw.get('base',0):.2f}"],
        ["FINAL SCORE",  "—",                           f"{raw.get('final',0):.2f}"],
    ]

    bt = Table(breakdown_data, colWidths=[60*mm, 50*mm, 60*mm])
    bt.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (-1, 0),  colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR',   (0, 0), (-1, 0),  BLUE),
        ('FONTNAME',    (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',    (0, 0), (-1, -1), 9),
        ('TEXTCOLOR',   (0, 1), (-1, -1), TEXT),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [PANEL, colors.HexColor('#0a0a15')]),
        ('GRID',        (0, 0), (-1, -1), 0.5, colors.HexColor('#1a1a2e')),
        ('PADDING',     (0, 0), (-1, -1), 7),
        ('TEXTCOLOR',   (0, -1), (-1, -1), sev_color),
        ('FONTNAME',    (0, -1), (-1, -1), 'Helvetica-Bold'),
    ]))
    elements.append(bt)
    elements.append(Spacer(1, 6*mm))

    # ── AI Analyst Briefing ───────────────────────────────────
    if record.get("ai_summary"):
        elements.append(Paragraph("■ AI ANALYST BRIEFING", title_style))
        brief_style = ParagraphStyle(
            'Brief',
            fontSize=9,
            textColor=TEXT,
            fontName='Helvetica',
            leading=16,
            leftIndent=5*mm,
            spaceAfter=6*mm,
            borderPad=5*mm,
        )
        elements.append(Paragraph(record["ai_summary"], brief_style))
        elements.append(Spacer(1, 4*mm))

    # ── Tags ──────────────────────────────────────────────────
    tags = record.get("tags", [])
    if tags:
        elements.append(Paragraph("■ THREAT TAGS", title_style))
        tag_text = "  ·  ".join(tags[:15])
        tag_style = ParagraphStyle(
            'Tags',
            fontSize=8,
            textColor=GOLD,
            fontName='Helvetica',
            spaceAfter=6*mm,
        )
        elements.append(Paragraph(tag_text, tag_style))

    # ── Recommended Actions ───────────────────────────────────
    elements.append(Paragraph("■ RECOMMENDED ACTIONS", title_style))

    sev = record.get("severity", "LOW")
    actions = {
        "CRITICAL": [
            "🔴 IMMEDIATE: Block IP at perimeter firewall",
            "🔴 Add to SIEM watchlist with Priority-1 alerting",
            "🔴 Escalate to Tier-2 analyst for attribution",
            "🔴 Check internal logs for any connections to this IP",
            "🔴 Initiate incident response procedure",
        ],
        "HIGH": [
            "🟠 Block IP at perimeter firewall within 1 hour",
            "🟠 Add to SIEM watchlist with Priority-2 alerting",
            "🟠 Assign to on-call analyst for investigation",
            "🟠 Review firewall logs for past connections",
        ],
        "MEDIUM": [
            "🟡 Add IP to monitoring watchlist",
            "🟡 Review in next analyst shift",
            "🟡 Consider blocking if activity continues",
        ],
        "LOW": [
            "🟢 Log and monitor — no immediate action required",
            "🟢 Review if multiple LOW threats share same ASN",
        ],
    }

    action_style = ParagraphStyle(
        'Action',
        fontSize=9,
        textColor=TEXT,
        fontName='Helvetica',
        leading=16,
        spaceAfter=2*mm,
    )
    for action in actions.get(sev, actions["LOW"]):
        elements.append(Paragraph(action, action_style))

    elements.append(Spacer(1, 8*mm))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=MUTED))

    # ── Footer ────────────────────────────────────────────────
    footer_style = ParagraphStyle(
        'Footer',
        fontSize=7,
        textColor=MUTED,
        fontName='Helvetica',
        alignment=TA_CENTER,
        spaceBefore=3*mm,
    )
    elements.append(Paragraph(
        f"Generated by PHANTØM Threat Intelligence Platform · {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
        footer_style
    ))

    doc.build(elements)
    return buffer.getvalue()
