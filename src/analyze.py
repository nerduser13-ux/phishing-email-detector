from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, EmailLog
from detector import analyze_email
import json

analyze = Blueprint('analyze', __name__)


@analyze.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze_email_route():
    if request.method == 'POST':
        subject = request.form.get('subject', '').strip()
        sender = request.form.get('sender', '').strip()
        reply_to = request.form.get('reply_to', '').strip()
        body = request.form.get('body', '').strip()
        attachments = request.form.get('attachments', '').strip()

        # Basic validation
        if not subject or not sender or not body:
            flash('Subject, sender, and body are required.', 'danger')
            return redirect(url_for('analyze.analyze_email_route'))

        # Run detection
        result = analyze_email(subject, sender, reply_to, body, attachments)

        # Save to database
        log = EmailLog(
            submitted_by=current_user.id,
            email_subject=subject,
            email_sender=sender,
            email_body=body,
            risk_level=result['risk_level'],
            risk_score=result['risk_score'],
            findings=json.dumps(result['findings']),
            is_quarantined=(result['risk_level'] == 'RED')
        )
        db.session.add(log)
        db.session.commit()

        return render_template(
            'result.html',
            result=result,
            subject=subject,
            sender=sender
        )

    return render_template('analyze.html')
