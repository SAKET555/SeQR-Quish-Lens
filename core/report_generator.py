"""
PDF Security Audit Report Generator Module.
Generates an executive, downloadable PDF report summarizing scan findings,
VirusTotal engine results, DNS lookups, heuristic flags, and remediation steps.
"""

import io
from typing import Dict, Any, List
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)


class ReportGenerator:
    """
    Generates professional PDF security audit reports in memory.
    """

    @classmethod
    def generate_pdf(
        cls,
        raw_text: str,
        payload_type: str,
        heuristic_result: Dict[str, Any],
        redirect_result: Dict[str, Any],
        vt_result: Dict[str, Any],
        risk_summary: Dict[str, Any],
        dns_result: Dict[str, Any]
    ) -> bytes:
        """
        Creates a complete PDF report as bytes.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom PDF Styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            alignment=0
        )
        subtitle_style = ParagraphStyle(
            'DocSubTitle',
            parent=styles['Normal'],
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#64748b"),
            fontName="Helvetica"
        )
        section_heading = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0284c7"),
            fontName="Helvetica-Bold",
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyDark',
            parent=styles['Normal'],
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#334155")
        )
        code_style = ParagraphStyle(
            'CodeText',
            parent=styles['Code'],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#0284c7"),
            backColor=colors.HexColor("#f1f5f9"),
            borderColor=colors.HexColor("#cbd5e1"),
            borderWidth=0.5,
            borderPadding=4
        )

        story = []

        # 1. Header & Title Block
        story.append(Paragraph("🛡️ SeQR QuishLens — Executive Security Audit Report", title_style))
        story.append(Spacer(1, 3))
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        story.append(Paragraph(f"Generated on: <b>{now_str}</b> | Engine Version: <b>v3.0 Production</b>", subtitle_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

        # 2. Verdict Banner Box
        verdict = risk_summary.get("verdict", "UNKNOWN")
        score = risk_summary.get("risk_score", 0)

        v_bg_color = colors.HexColor("#dcfce7") if verdict == "SAFE" else (
            colors.HexColor("#fef3c7") if verdict == "SUSPICIOUS" else colors.HexColor("#fee2e2")
        )
        v_text_color = colors.HexColor("#15803d") if verdict == "SAFE" else (
            colors.HexColor("#b45309") if verdict == "SUSPICIOUS" else colors.HexColor("#b91c1c")
        )

        verdict_p = Paragraph(f"<b>VERDICT: {verdict}</b> &nbsp;&nbsp;|&nbsp;&nbsp; Risk Score: <b>{score} / 100</b>", ParagraphStyle(
            'VerdictHeader', fontSize=14, leading=18, textColor=v_text_color, fontName="Helvetica-Bold", alignment=1
        ))
        summary_p = Paragraph(risk_summary.get("summary", ""), ParagraphStyle(
            'VerdictSummary', fontSize=9.5, leading=13, textColor=colors.HexColor("#334155"), alignment=1
        ))

        verdict_table = Table([[verdict_p], [summary_p]], colWidths=[540])
        verdict_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), v_bg_color),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOX', (0,0), (-1,-1), 1.5, v_text_color),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 12),
            ('RIGHTPADDING', (0,0), (-1,-1), 12),
        ]))
        story.append(verdict_table)
        story.append(Spacer(1, 14))

        # 3. Target Payload Summary Table
        story.append(Paragraph("📱 Target Payload & Technical Specifications", section_heading))
        
        dns_status_str = "Resolved" if dns_result.get("resolved") else f"Failed ({dns_result.get('error', 'NXDOMAIN')})"
        resolved_ip = dns_result.get("ip") or "None"

        spec_data = [
            [Paragraph("<b>Raw Payload Target</b>", body_style), Paragraph(f"<code>{raw_text[:80]}</code>", code_style)],
            [Paragraph("<b>Payload Classification</b>", body_style), Paragraph(payload_type, body_style)],
            [Paragraph("<b>DNS Resolution Status</b>", body_style), Paragraph(dns_status_str, body_style)],
            [Paragraph("<b>Resolved Target IP</b>", body_style), Paragraph(resolved_ip, body_style)],
        ]
        spec_table = Table(spec_data, colWidths=[160, 380])
        spec_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(spec_table)
        story.append(Spacer(1, 12))

        # 4. Zero-Day Heuristic Findings
        story.append(Paragraph("🔍 Zero-Day Heuristic Rule Audit Findings", section_heading))
        flags = heuristic_result.get("flags", [])
        if not flags:
            story.append(Paragraph("✅ <i>No suspicious heuristic rules triggered. Payload passed all static filters.</i>", body_style))
        else:
            h_data = [[Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Flag Title</b>", body_style), Paragraph("<b>Risk Points</b>", body_style)]]
            for f in flags:
                sev = f.get("severity", "MEDIUM")
                h_data.append([
                    Paragraph(f"<b>[{sev}]</b>", body_style),
                    Paragraph(f"<b>{f.get('title')}</b><br/><font size=8 color='#64748b'>{f.get('description')}</font>", body_style),
                    Paragraph(f"+{f.get('points')} pts", body_style)
                ])
            h_table = Table(h_data, colWidths=[80, 380, 80])
            h_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0284c7")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(h_table)

        story.append(Spacer(1, 12))

        # 5. VirusTotal Engine Intelligence
        story.append(Paragraph("🦠 VirusTotal Multi-Engine Threat Intelligence", section_heading))
        if vt_result.get("fallback_mode"):
            story.append(Paragraph(f"ℹ️ <i>{vt_result.get('reason', 'VirusTotal scan not available.')}</i>", body_style))
        else:
            stats = vt_result.get("stats", {})
            vt_text = (
                f"Malicious Engines: <b>{stats.get('malicious', 0)}</b> | "
                f"Suspicious: <b>{stats.get('suspicious', 0)}</b> | "
                f"Harmless: <b>{stats.get('harmless', 0)}</b> | "
                f"Undetected: <b>{stats.get('undetected', 0)}</b>"
            )
            story.append(Paragraph(vt_text, body_style))

        story.append(Spacer(1, 12))

        # 6. Actionable Security Recommendations
        story.append(Paragraph("🛡️ Actionable Remediation & Security Guidance", section_heading))
        for rec in risk_summary.get("recommendations", []):
            story.append(Paragraph(f"• {rec}", body_style))
            story.append(Spacer(1, 3))

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
