from flask import Blueprint, render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User

import bcrypt
import pyotp
import qrcode
import io
import base64

auth = Blueprint('auth', __name__)

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'analyst')

        # Check if user exists
        existing_user = User.query.filter_by(email=email).first()
        existing_username = User.query.filter_by(username=username).first()

        if existing_user:
            flash('Email already registered.', 'danger')
            return redirect(url_for('auth.register'))

        if existing_username:
            flash('Username already taken. Choose another.', 'danger')
            return redirect(url_for('auth.register'))

        # Hash password
        password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        # Generate OTP secret
        otp_secret = pyotp.random_base32()

        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            role=role,
            otp_secret=otp_secret,
            is_2fa_enabled=False
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Account created! Please set up 2FA.', 'success')
        return redirect(url_for('auth.setup_2fa', user_id=new_user.id))

    return render_template('register.html')


@auth.route('/setup-2fa/<int:user_id>')
def setup_2fa(user_id):
    user = db.session.get(User, user_id) or abort(404)
    otp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(
        name=user.email,
        issuer_name='PhishingDetector'
    )
    # Generate QR code
    qr = qrcode.make(otp_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('setup_2fa.html', qr_code=qr_base64, user=user)


@auth.route('/verify-2fa-setup/<int:user_id>', methods=['POST'])
def verify_2fa_setup(user_id):
    user = db.session.get(User, user_id) or abort(404)
    token = request.form.get('token')
    totp = pyotp.TOTP(user.otp_secret)

    if totp.verify(token):
        user.is_2fa_enabled = True
        db.session.commit()
        flash('2FA enabled successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))
    else:
        flash('Invalid code. Try again.', 'danger')
        return redirect(url_for('auth.setup_2fa', user_id=user_id))


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email not found.', 'danger')
            return redirect(url_for('auth.login'))

        if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            flash('Incorrect password.', 'danger')
            return redirect(url_for('auth.login'))

        # Store user id in session for 2FA step
        session['pre_2fa_user_id'] = user.id
        return redirect(url_for('auth.verify_2fa'))

    return render_template('login.html')


@auth.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = db.session.get(User, user_id) or abort(404)

    if request.method == 'POST':
        token = request.form.get('token')
        totp = pyotp.TOTP(user.otp_secret)

        if totp.verify(token):
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid 2FA code. Try again.', 'danger')

    return render_template('verify_2fa.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('auth.login'))
