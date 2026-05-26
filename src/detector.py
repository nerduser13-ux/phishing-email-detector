import re
from urllib.parse import urlparse

# ---- KEYWORD LISTS ----

URGENT_KEYWORDS = [
    'verify your account', 'urgent', 'immediate action', 'act now',
    'your account has been suspended', 'confirm your identity',
    'update your information', 'click here immediately',
    'limited time', 'expires soon', 'final notice',
    'your account will be closed', 'unusual activity detected',
    'security alert', 'unauthorized access', 'validate your account'
]

FINANCIAL_KEYWORDS = [
    'bank account', 'credit card', 'wire transfer', 'paypal',
    'send money', 'payment required', 'invoice attached',
    'refund pending', 'tax return', 'prize money',
    'you have won', 'lottery', 'inheritance', 'million dollars'
]

SUSPICIOUS_PHRASES = [
    'dear customer', 'dear user', 'dear account holder',
    'click the link below', 'do not share this email',
    'kindly provide', 'verify immediately', 'respond immediately',
    'your password has expired', 'login to confirm'
]

SAFE_DOMAINS = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'github.com', 'linkedin.com', 'twitter.com', 'facebook.com',
    'youtube.com', 'wikipedia.org', 'stackoverflow.com'
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.link']

DANGEROUS_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.vbs', '.js', '.jar',
    '.scr', '.pif', '.com', '.ps1', '.msi', '.docm', '.xlsm'
]


# ---- HELPER FUNCTIONS ----

def extract_urls(text):
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return url_pattern.findall(text)


def is_ip_based_url(url):
    try:
        host = urlparse(url).hostname
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        return bool(ip_pattern.match(host))
    except:
        return False


def has_suspicious_tld(url):
    try:
        host = urlparse(url).hostname
        if host:
            for tld in SUSPICIOUS_TLDS:
                if host.endswith(tld):
                    return True
    except:
        pass
    return False


def is_misleading_domain(url):
    try:
        host = urlparse(url).hostname
        if host:
            for safe in SAFE_DOMAINS:
                safe_name = safe.split('.')[0]
                if safe_name in host and not host.endswith(safe):
                    return True
    except:
        pass
    return False


def check_sender_spoofing(sender, reply_to):
    if not sender or not reply_to:
        return False
    sender_domain = sender.split('@')[-1].strip().lower() if '@' in sender else ''
    reply_domain = reply_to.split('@')[-1].strip().lower() if '@' in reply_to else ''
    return sender_domain != reply_domain and reply_domain != ''


def check_attachments(attachments_str):
    findings = []
    if not attachments_str:
        return findings
    attachments = [a.strip().lower() for a in attachments_str.split(',')]
    for attachment in attachments:
        for ext in DANGEROUS_EXTENSIONS:
            if attachment.endswith(ext):
                findings.append(f'Dangerous attachment detected: {attachment}')
    return findings


# ---- MAIN ANALYSIS FUNCTION ----

def analyze_email(subject, sender, reply_to, body, attachments):
    score = 0
    findings = []

    body_lower = body.lower()
    subject_lower = subject.lower()
    full_text = body_lower + ' ' + subject_lower

    # 1. Check urgent keywords
    for keyword in URGENT_KEYWORDS:
        if keyword in full_text:
            score += 15
            findings.append(f'Urgency keyword detected: "{keyword}"')
            break

    # 2. Check financial keywords
    financial_hits = []
    for keyword in FINANCIAL_KEYWORDS:
        if keyword in full_text:
            financial_hits.append(keyword)
    if financial_hits:
        score += 10 * len(financial_hits[:2])
        findings.append(f'Financial keywords detected: {", ".join(financial_hits[:2])}')

    # 3. Check suspicious phrases
    for phrase in SUSPICIOUS_PHRASES:
        if phrase in full_text:
            score += 10
            findings.append(f'Suspicious phrase detected: "{phrase}"')
            break

    # 4. Analyze URLs in body
    urls = extract_urls(body)
    for url in urls:
        if is_ip_based_url(url):
            score += 25
            findings.append(f'IP-based URL detected: {url}')
        if has_suspicious_tld(url):
            score += 20
            findings.append(f'Suspicious domain extension in URL: {url}')
        if is_misleading_domain(url):
            score += 30
            findings.append(f'Misleading domain detected: {url}')

    # 5. Check sender spoofing
    if check_sender_spoofing(sender, reply_to):
        score += 30
        findings.append(
            f'Sender/Reply-To mismatch detected: '
            f'Sender={sender}, Reply-To={reply_to}'
        )

    # 6. Check attachments
    attachment_findings = check_attachments(attachments)
    if attachment_findings:
        score += 25 * len(attachment_findings)
        findings.extend(attachment_findings)

    # 7. Check for no findings (clean email)
    if not findings:
        findings.append('No phishing indicators detected.')

    # ---- DETERMINE RISK LEVEL ----
    if score >= 50:
        risk_level = 'RED'
    elif score >= 20:
        risk_level = 'YELLOW'
    else:

