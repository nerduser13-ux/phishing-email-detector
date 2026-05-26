# System Architecture

## Overview

The Phishing Email Detector is a Flask-based web application with the following layers:

## Components

- **Frontend:** HTML/CSS/JavaScript templates
- **Backend:** Python Flask with Blueprint architecture
- **Database:** SQLite with SQLAlchemy ORM
- **Auth:** Flask-Login + PyOTP (TOTP-based 2FA)
- **Detection Engine:** Heuristic-based analysis (detector.py)

## DevSecOps Pipeline

Build → SAST → Dependency Scan → Test → Deploy

## Security Controls

- bcrypt password hashing
- TOTP Two-Factor Authentication
- Role-Based Access Control (Admin/Analyst)
- Input sanitization
- Parameterized SQL queries
- Automatic quarantine for RED risk emails
