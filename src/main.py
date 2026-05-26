from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, EmailLog
from functools import wraps

main = Blueprint('main', __name__)

# Admin-only decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated_function


@main.route('/')
@login_required
def dashboard():
    recent_logs = EmailLog.query.filter_by(
        submitted_by=current_user.id
    ).order_by(EmailLog.analyzed_at.desc()).limit(10).all()
    return render_template('dashboard.html', logs=recent_logs)


@main.route('/quarantine')
@login_required
@admin_required
def quarantine():
    quarantined = EmailLog.query.filter_by(is_quarantined=True).all()
    return render_template('quarantine.html', emails=quarantined)


@main.route('/history')
@login_required
def history():
    logs = EmailLog.query.filter_by(
        submitted_by=current_user.id
    ).order_by(EmailLog.analyzed_at.desc()).all()
    return render_template('history.html', logs=logs)
