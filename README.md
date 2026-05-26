# 🛡️ Phishing Email Detector

A web-based phishing email detection tool built with DevSecOps principles for ICT932 – Cybersecurity Testing and Assurance.

## 👥 Team

SecureOps Team | S1-2026

## 📋 Project Overview

This tool analyzes emails and identifies phishing attempts using:

- URL analysis (IP-based URLs, suspicious TLDs, misleading domains)
- Keyword and phrase pattern matching
- Email header and Reply-To mismatch detection
- Dangerous attachment detection
- Risk scoring system (RED / YELLOW / GREEN verdict)

## 🏗️ Project Structure

```
phishing-email-detector/
├── src/                         # Source code
│   ├── app.py                   # Main Flask application
│   ├── auth.py                  # Authentication routes (login, register, 2FA)
│   ├── main.py                  # Dashboard, history, quarantine routes
│   ├── analyze.py               # Email analysis routes
│   ├── detector.py              # Phishing detection engine
│   ├── models.py                # Database models
│   ├── config.py                # App configuration
│   ├── export.py                # PDF export feature
│   └── templates/               # HTML templates
│       ├── base.html
│       ├── login.html
│       ├── register.html
│       ├── setup_2fa.html
│       ├── verify_2fa.html
│       ├── dashboard.html
│       ├── analyze.html
│       ├── result.html
│       ├── history.html
│       └── quarantine.html
├── tests/                       # Automated tests
│   └── test_detector.py         # Unit tests for detection engine
├── docs/                        # Documentation
│   └── architecture.md
├── ci-cd/                       # Pipeline reference files
│   └── devsecops-pipeline.yml
├── .github/
│   └── workflows/
│       └── devsecops-pipeline.yml  # GitHub Actions CI/CD pipeline
├── .zap/
│   └── rules.tsv                # OWASP ZAP ignore rules
├── .gitignore
├── requirements.txt             # Python dependencies
└── README.md
```

## ⚙️ Setup Instructions

### Prerequisites

- Python 3.11+
- Git

### Installation

1. Clone the repository

```bash
git clone https://github.com/nerduser13-ux/phishing-email-detector.git
cd phishing-email-detector
```

2. Create and activate virtual environment

```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
```

3. Install dependencies

```bash
pip install -r requirements.txt
```

4. Run the application

```bash
cd src
python app.py
```

5. Open in browser
   http://127.0.0.1:5000

## 🔐 Features

- Secure login with bcrypt password hashing
- Two-Factor Authentication (2FA) via Google Authenticator
- Role-Based Access Control (Admin / Analyst)
- Phishing email analysis with risk scoring
- Automatic quarantine for HIGH risk emails
- Analysis history tracking
- Admin quarantine dashboard

## 🔒 Security Tools Used

| Tool      | Purpose                                    |
| --------- | ------------------------------------------ |
| Bandit    | Static Application Security Testing (SAST) |
| pip-audit | Dependency vulnerability scanning          |
| Flake8    | Code quality linting                       |
| pytest    | Automated unit testing                     |

## 🚀 CI/CD Pipeline

Automated pipeline runs on every push to `main`:
Build → SAST (Bandit) → Dependency Scan → Tests → Deploy

## 🧪 Running Tests

```bash
pytest tests/ -v
```

## 📁 OWASP Top 10 Coverage

| OWASP | Description               | Mitigation            |
| ----- | ------------------------- | --------------------- |
| A03   | Injection                 | Parameterized queries |
| A05   | Security Misconfiguration | Hardened HTTP headers |
| A07   | Authentication Failures   | 2FA + bcrypt hashing  |

## ⚠️ Ethical Use

This tool is for educational purposes only. Only analyze emails you have permission to test.
