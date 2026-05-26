import email
from email import policy
from bs4 import BeautifulSoup
import re


def extract_email_address(raw):
    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', raw)
    return match.group(0) if match else raw


def parse_raw_email(raw_email_text):
    try:
        msg = email.message_from_string(
            raw_email_text,
            policy=policy.default
        )

        subject = msg.get('Subject', '') or ''
        sender = msg.get('From', '') or ''
        reply_to = msg.get('Reply-To', '') or ''
        to = msg.get('To', '') or ''
        date = msg.get('Date', '') or ''

        sender_clean = extract_email_address(sender)
        reply_to_clean = extract_email_address(reply_to)

        body = ''
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get('Content-Disposition', ''))

                if 'attachment' in disposition:
                    filename = part.get_filename()
                    if filename:
                        attachments.append(filename)

                elif content_type == 'text/plain':
                    try:
                        body += part.get_content()
                    except Exception:
                        body += str(part.get_payload(decode=True))

                elif content_type == 'text/html' and not body:
                    try:
                        html = part.get_content()
                        soup = BeautifulSoup(html, 'html.parser')
                        body += soup.get_text(separator=' ')
                    except Exception:
                        pass
        else:
            content_type = msg.get_content_type()
            if content_type == 'text/html':
                try:
                    html = msg.get_content()
                    soup = BeautifulSoup(html, 'html.parser')
                    body = soup.get_text(separator=' ')
                except Exception:
                    body = str(msg.get_payload(decode=True))
            else:
                try:
                    body = msg.get_content()
                except Exception:
                    body = str(msg.get_payload(decode=True))

        return {
            'subject': subject.strip(),
            'sender': sender_clean.strip(),
            'reply_to': reply_to_clean.strip(),
            'to': to.strip(),
            'date': date.strip(),
            'body': body.strip(),
            'attachments': ', '.join(attachments),
            'parse_success': True,
            'error': None
        }

    except Exception as e:
        return {
            'subject': '',
            'sender': '',
            'reply_to': '',
            'to': '',
            'date': '',
            'body': '',
            'attachments': '',
            'parse_success': False,
            'error': str(e)
        }