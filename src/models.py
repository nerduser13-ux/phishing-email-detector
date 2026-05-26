from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='analyst')  # admin or analyst
    otp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'


class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submitted_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    email_subject = db.Column(db.String(200))
    email_sender = db.Column(db.String(200))
    email_body = db.Column(db.Text)
    risk_level = db.Column(db.String(10))  # RED, YELLOW, GREEN
    risk_score = db.Column(db.Integer)
    findings = db.Column(db.Text)
    is_quarantined = db.Column(db.Boolean, default=False)
    analyzed_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<EmailLog {self.id} - {self.risk_level}>'
