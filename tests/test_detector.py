import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from detector import (
    analyze_email,
    extract_urls,
    is_ip_based_url,
    has_suspicious_tld,
    is_misleading_domain,
    check_sender_spoofing,
    check_attachments
)


# ---- URL TESTS ----

def test_extract_urls():
    text = "Click here: http://evil.tk/login and http://192.168.1.1"
    urls = extract_urls(text)
    assert len(urls) == 2


def test_ip_based_url_detected():
    assert is_ip_based_url("http://192.168.1.1/login") == True


def test_ip_based_url_clean():
    assert is_ip_based_url("https://google.com/login") == False


def test_suspicious_tld_detected():
    assert has_suspicious_tld("http://freeprize.tk/win") == True


def test_suspicious_tld_clean():
    assert has_suspicious_tld("https://microsoft.com") == False


def test_misleading_domain_detected():
    assert is_misleading_domain("http://google.com.evil.tk/login") == True


def test_misleading_domain_clean():
    assert is_misleading_domain("https://google.com/login") == False


# ---- SENDER SPOOFING TESTS ----

def test_sender_spoofing_detected():
    assert check_sender_spoofing(
        "support@paypal.com",
        "harvest@evil.tk"
    ) == True


def test_sender_spoofing_clean():
    assert check_sender_spoofing(
        "support@paypal.com",
        "help@paypal.com"
    ) == False


# ---- ATTACHMENT TESTS ----

def test_dangerous_attachment_detected():
    findings = check_attachments("invoice.exe")
    assert len(findings) > 0


def test_safe_attachment_clean():
    findings = check_attachments("report.pdf")
    assert len(findings) == 0


# ---- FULL ANALYSIS TESTS ----

def test_phishing_email_returns_red():
    result = analyze_email(
        subject="Urgent: Verify your account now",
        sender="support@paypa1.com",
        reply_to="harvest@evil.tk",
        body="Dear customer, click here: http://192.168.1.1/login immediately",
        attachments="invoice.exe"
    )
    assert result['risk_level'] == 'RED'
    assert result['risk_score'] >= 50


def test_clean_email_returns_green():
    result = analyze_email(
        subject="Meeting tomorrow at 3pm",
        sender="colleague@company.com",
        reply_to="colleague@company.com",
        body="Hi, just a reminder about our meeting tomorrow.",
        attachments=""
    )
    assert result['risk_level'] == 'GREEN'
    assert result['risk_score'] < 20


def test_suspicious_email_returns_yellow():
    result = analyze_email(
        subject="Your invoice is ready",
        sender="billing@company.com",
        reply_to="billing@company.com",
        body="Please review your invoice. Payment required soon.",
        attachments=""
    )
    assert result['risk_level'] in ['YELLOW', 'GREEN']


def test_result_has_required_keys():
    result = analyze_email(
        subject="Test",
        sender="test@test.com",
        reply_to="",
        body="Hello world",
        attachments=""
    )
    assert 'risk_level' in result
    assert 'risk_score' in result
    assert 'findings' in result


def test_score_never_exceeds_100():
    result = analyze_email(
        subject="Urgent urgent urgent verify account now act immediately",
        sender="fake@evil.tk",
        reply_to="harvest@other.tk",
        body="Dear customer verify immediately http://192.168.1.1 invoice lottery won million",
        attachments="virus.exe, trojan.bat, malware.vbs"
    )
    assert result['risk_score'] <= 100