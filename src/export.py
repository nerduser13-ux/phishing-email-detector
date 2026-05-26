from flask import Blueprint, Response, abort
from flask_login import login_required, current_user
from models import EmailLog
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import io
import json
from datetime import datetime

export = Blueprint('export', __name__)


def generate_pdf_report(log):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=inch,
        leftMargin=inch,
        topMargin=inch,
        bottomMargin=inch
    )

    styles = getSampleStyleSheet()
    elements = []

    # ---- TITLE ----
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=22,
        textColor=colors.HexColor('#1a1d2e'),
        spaceAfter=6,
        alignment=TA_CENTER
    )
    elements.append(Paragraph("Phishing Email Analysis Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ParagraphStyle('sub', parent=styles['Normal'],
                       fontSize=10, textColor=colors.grey,
                       alignment=TA_CENTER)
    ))
    elements.append(Spacer(1, 0.3 * inch))

    # ---- RISK VERDICT BOX ----
    if log.risk_level == 'RED':
        risk_color = colors.HexColor('#e53e3e')
        risk_text = 'HIGH RISK — PHISHING DETECTED'
    elif log.risk_level == 'YELLOW':
        risk_color = colors.HexColor('#d69e2e')
        risk_text = 'MEDIUM RISK — SUSPICIOUS EMAIL'
    else:
        risk_color = colors.HexColor('#38a169')
        risk_text = 'LOW RISK — EMAIL APPEARS SAFE'

    verdict_style = ParagraphStyle(
        'Verdict',
        parent=styles['Normal'],
        fontSize=14,
        textColor=colors.white,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    verdict_table = Table(
        [[Paragraph(risk_text, verdict_style)]],
        colWidths=[6.5 * inch]
    )
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), risk_color),
        ('ROUNDEDCORNERS', [8]),
        ('TOPPADDING', (0, 0), (-1, -1), 14),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
    ]))
    elements.append(verdict_table)
    elements.append(Spacer(1, 0.2 * inch))

    # ---- RISK SCORE ----
    score_style = ParagraphStyle(
        'Score',
        parent=styles['Normal'],
        fontSize=16,
        textColor=colors.HexColor('#1a1d2e'),
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    elements.append(Paragraph(
        f"Risk Score: {log.risk_score}/100",
        score_style
    ))
    elements.append(Spacer(1, 0.3 * inch))

    # ---- EMAIL DETAILS TABLE ----
    heading_style = ParagraphStyle(
        'Heading',
        parent=styles['Normal'],
        fontSize=13,
        textColor=colors.HexColor('#1a1d2e'),
        fontName='Helvetica-Bold',
        spaceAfter=8
    )
    elements.append(Paragraph("Email Details", heading_style))

    detail_data = [
        ['Field', 'Value'],
        ['Subject', log.email_subject or 'N/A'],
        ['Sender', log.email_sender or 'N/A'],
        ['Risk Level', log.risk_level],
        ['Risk Score', f"{log.risk_score}/100"],
        ['Quarantined', 'Yes' if log.is_quarantined else 'No'],
        ['Analyzed At', log.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')],
    ]

    detail_table = Table(detail_data, colWidths=[2 * inch, 4.5 * inch])
    detail_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f7fafc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1),
         [colors.HexColor('#f7fafc'), colors.HexColor('#edf2f7')]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e0')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(detail_table)
    elements.append(Spacer(1, 0.3 * inch))

    # ---- FINDINGS ----
    elements.append(Paragraph("Analysis Findings", heading_style))

    findings = json.loads(log.findings) if log.findings else ['No findings recorded.']

    finding_style = ParagraphStyle(
        'Finding',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#2d3748'),
        leftIndent=10,
        spaceAfter=4
    )

    for i, finding in enumerate(findings, 1):
        if 'detected' in finding.lower() or 'mismatch' in finding.lower():
            dot = '🔴'
        elif 'no phishing' in finding.lower():
            dot = '🟢'
        else:
            dot = '🟡'
        elements.append(Paragraph(f"{i}. {finding}", finding_style))

    elements.append(Spacer(1, 0.3 * inch))

    # ---- FOOTER ----
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.grey,
        alignment=TA_CENTER
    )
    elements.append(Paragraph(
        "Generated by PhishingDetector | ICT932 – SecureOps Team | S1-2026",
        footer_style
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer


@export.route('/export/pdf/<int:log_id>')
@login_required
def export_pdf(log_id):
    log = EmailLog.query.get_or_404(log_id)

    # Only allow owner or admin
    if log.submitted_by != current_user.id and current_user.role != 'admin':
        abort(403)

    buffer = generate_pdf_report(log)
    filename = f"phishing_report_{log_id}_{log.risk_level}.pdf"

    return Response(
        buffer,
        mimetype='application/pdf',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )
