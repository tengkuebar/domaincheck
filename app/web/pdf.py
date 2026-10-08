"""PDF export of a finished report, built with ReportLab (pure Python, no system libraries).

Uses the built-in Helvetica and Courier fonts, which only cover Western European text, so any
character outside that range is replaced rather than drawn as a broken box. Status is always shown
as a word, never as a colour or symbol alone.
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from html import escape
from typing import Any

from reportlab.graphics.shapes import Drawing, Rect
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.scanning.store import ScanResult

INK = colors.HexColor("#14181F")
MUTED = colors.HexColor("#566070")
LINE = colors.HexColor("#DFE3EA")
ACCENT = colors.HexColor("#0B5FD6")
TONES = {  # status -> (word, text colour)
    "pass": ("GOOD", colors.HexColor("#14612B")),
    "warn": ("IMPROVE", colors.HexColor("#7A4E00")),
    "fail": ("FIX NOW", colors.HexColor("#9C1128")),
    "not_detected": ("NOT DETECTED", colors.HexColor("#38414F")),
    "error": ("COULD NOT CHECK", colors.HexColor("#38414F")),
}
BAND_COLORS = {
    "good": colors.HexColor("#1F8A3D"),
    "warn": colors.HexColor("#C98A00"),
    "bad": colors.HexColor("#C0283D"),
}
PAGE_W = A4[0] - 40 * mm  # usable width with 20 mm margins


def _s(name: str, **kw: Any) -> ParagraphStyle:
    base = {"fontName": "Helvetica", "fontSize": 10, "leading": 14, "textColor": INK}
    return ParagraphStyle(name, **{**base, **kw})


STYLES = {
    "title": _s("title", fontName="Helvetica-Bold", fontSize=22, leading=26),
    "h2": _s(
        "h2",
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=1,
    ),
    "h3": _s("h3", fontName="Helvetica-Bold", fontSize=11, leading=15, keepWithNext=1),
    "body": _s("body", spaceAfter=4),
    "small": _s("small", fontSize=8.5, leading=12, textColor=MUTED),
    "label": _s(
        "label", fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=MUTED, spaceBefore=6
    ),
    "mono": _s("mono", fontName="Courier", fontSize=8, leading=11),
    "step": _s("step", leftIndent=14, firstLineIndent=-10, spaceAfter=2),
    "cell": _s("cell", fontSize=9, leading=12),
    "cellb": _s("cellb", fontName="Helvetica-Bold", fontSize=9, leading=12),
    "bignum": _s("bignum", fontName="Helvetica-Bold", fontSize=34, leading=38),
}


def clean(text: object) -> str:
    """Make text safe for ReportLab: escape markup and drop characters the base fonts lack."""
    raw = "" if text is None else str(text)
    return escape(raw.encode("cp1252", errors="replace").decode("cp1252"), quote=False)


def _p(text: object, style: str = "body", **kw: Any) -> Paragraph:
    s = STYLES[style]
    return Paragraph(clean(text), ParagraphStyle(style + "x", parent=s, **kw) if kw else s)


def _status_word(status: str) -> Paragraph:
    word, color = TONES[status]
    return Paragraph(
        f'<font color="{color.hexval().replace("0x", "#")}"><b>{word}</b></font>', STYLES["cell"]
    )


def _bar(pct: int | None, tone: str, width: float = 38 * mm) -> Drawing:
    d = Drawing(width, 6)
    d.add(Rect(0, 0, width, 6, rx=3, ry=3, fillColor=LINE, strokeColor=None))
    if pct:
        d.add(
            Rect(
                0,
                0,
                width * pct / 100,
                6,
                rx=3,
                ry=3,
                fillColor=BAND_COLORS[tone],
                strokeColor=None,
            )
        )
    return d


def _evidence_value(value: Any) -> str:
    if value is None:
        return "none"
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    return text if len(text) <= 400 else text[:397] + "..."


def render_report_pdf(result: ScanResult, dash: dict[str, Any]) -> bytes:
    """Build the PDF for a finished scan. ``dash`` comes from ``build_dashboard``."""
    buffer = io.BytesIO()
    checked = datetime.fromtimestamp(result.created_at, UTC).strftime("%Y-%m-%d %H:%M UTC")

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(
            20 * mm,
            10 * mm,
            clean(
                f"DomainCheck report for {result.domain} - passive checks, snapshot of {checked}"
            ),
        )
        canvas.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=clean(f"DomainCheck report: {result.domain}"),
        author="DomainCheck",
    )
    story: list[Any] = []

    # --- summary ---
    story.append(_p("DomainCheck report", "small"))
    story.append(_p(result.domain, "title"))
    story.append(_p(f"Checked {checked}", "small"))
    story.append(Spacer(1, 8))

    score, band = dash["score"], dash["band"]
    if score is not None and band:
        sentence = f"{band[1]}."
        if dash["weakest"] and dash["weakest"]["pct"] is not None and dash["weakest"]["pct"] < 100:
            sentence += f" {dash['weakest']['name']} is the weakest area."
        after = dash["score_after"]
        if after is not None and after > score:
            sentence += (
                f" Fixing the top items below would lift the score from {score} to about {after}."
            )
        counts = dash["counts"]
        parts = [
            f"{counts['fail']} to fix",
            f"{counts['warn']} to improve",
            f"{counts['not_detected']} not detected",
            f"{counts['pass']} good",
        ]
        if counts["error"]:
            parts.append(f"{counts['error']} could not be checked")
        summary = Table(
            [
                [
                    [
                        _p(score, "bignum", textColor=BAND_COLORS[band[0]], alignment=TA_CENTER),
                        _p("out of 100", "small", alignment=TA_CENTER),
                    ],
                    [_p(sentence, "body"), _p(", ".join(parts), "small")],
                ]
            ],
            colWidths=[36 * mm, PAGE_W - 36 * mm],
        )
        summary.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (0, 0), (0, 0), "CENTER"),
                    ("LINEAFTER", (0, 0), (0, 0), 0.5, LINE),
                    ("BOX", (0, 0), (-1, -1), 0.6, LINE),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(summary)
    else:
        story.append(_p("No check could be scored, so there is no score.", "body"))

    # --- areas ---
    if dash["categories"]:
        story.append(_p("Areas", "h2"))
        table_rows = []
        for cat in dash["categories"]:
            checks = ", ".join(
                f"{r['short']} ({TONES[r['finding'].status][0].title()})" for r in cat["rows"]
            )
            pct = cat["pct"]
            tone = cat["band"][0] if cat["band"] else "warn"
            table_rows.append(
                [
                    [_p(cat["name"], "cellb"), _p(cat["blurb"], "small")],
                    [_bar(pct, tone), _p(f"{pct}%" if pct is not None else "not scored", "cellb")],
                    _p(checks, "cell"),
                ]
            )
        t = Table(table_rows, colWidths=[48 * mm, 46 * mm, PAGE_W - 94 * mm])
        t.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(t)

    # --- fix first ---
    story.append(_p("Fix these first", "h2"))
    if dash["fix_first"]:
        story.append(
            _p(
                "Ordered by how many score points each fix is worth. Effort is a typical estimate.",
                "small",
            )
        )
        rows = [
            [
                _p("#", "label"),
                _p("FIX", "label"),
                _p("WHAT TO DO", "label"),
                _p("POINTS", "label"),
                _p("EFFORT", "label"),
            ]
        ]
        for f in dash["fix_first"]:
            rows.append(
                [
                    _p(f["rank"], "cell"),
                    _p(f["title"], "cellb"),
                    _p(f["action"], "cell"),
                    _p(f"+{f['gain']}", "cellb"),
                    _p(f["effort"], "cell"),
                ]
            )
        t = Table(
            rows,
            colWidths=[
                9 * mm,
                42 * mm,
                PAGE_W - 9 * mm - 42 * mm - 22 * mm - 22 * mm,
                22 * mm,
                22 * mm,
            ],
            repeatRows=1,
        )
        t.setStyle(
            TableStyle(
                [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE)]
            )
        )
        story.append(t)
    else:
        story.append(_p("Nothing to fix. Every check that ran passed.", "body"))

    # --- findings ---
    story.append(_p("All findings", "h2"))
    for r in dash["rows"]:
        f = r["finding"]
        word, color = TONES[f.status]
        head = Paragraph(
            f'<font color="{color.hexval().replace("0x", "#")}"><b>{word}</b></font>&nbsp;&nbsp;{clean(f.title)}',
            STYLES["h3"],
        )
        block: list[Any] = [head, _p(f.explanation, "body")]
        if r["gain"] > 0:
            block.append(_p(f"Worth about +{r['gain']} points if fixed.", "small"))
        story.append(KeepTogether(block))
        if f.evidence:
            story.append(_p("EVIDENCE", "label"))
            for k, v in f.evidence.items():
                story.append(_p(f"{str(k).replace('_', ' ')}: {_evidence_value(v)}", "mono"))
        if r["fix"]:
            fix = r["fix"]
            story.append(
                _p(
                    f"HOW TO FIX{' - ABOUT ' + fix['effort'].upper() if fix['effort'] else ''}",
                    "label",
                )
            )
            story.append(_p(fix["summary"], "body"))
            for provider in fix["providers"]:
                story.append(_p(provider["name"], "cellb", spaceBefore=3))
                for i, step in enumerate(provider["steps"], 1):
                    story.append(_p(f"{i}.  {step}", "step"))
            story.append(
                _p(
                    "Provider screens change. If a step does not match, check your provider's help pages.",
                    "small",
                )
            )
        story.append(Spacer(1, 8))

    # --- method ---
    story.append(_p("How the score works", "h2"))
    story.append(
        _p(
            "Each check has a weight. A pass earns the full weight, a warning half, and a fail none. "
            '"Not detected" counts as a warning, and a check that could not run is left out. '
            "Weights are a judgement call. This report comes from passive checks (DNS records, the "
            "certificate and the home page) and is a snapshot, not a full security assessment.",
            "body",
        )
    )
    if dash["weights"]:
        story.append(
            _p(
                "Weights: "
                + ", ".join(f"{w['short']} {w['weight']}" for w in dash["weights"])
                + ".",
                "small",
            )
        )

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
