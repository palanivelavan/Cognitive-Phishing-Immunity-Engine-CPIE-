import base64
import re
from googleapiclient.discovery import build


def get_gmail_service(credentials):
    return build('gmail', 'v1', credentials=credentials)


def fetch_inbox_metadata(service, max_results=20):
    try:
        results = service.users().messages().list(
            userId='me',
            maxResults=max_results,
            labelIds=['INBOX']
        ).execute()

        messages = results.get('messages', [])
        mail_list = []

        for msg in messages:
            m_data = service.users().messages().get(
                userId='me',
                id=msg['id'],
                format='metadata',
                metadataHeaders=['Subject', 'From', 'Date',
                                 'Authentication-Results', 'Received-SPF']
            ).execute()

            headers = m_data.get('payload', {}).get('headers', [])
            subject = _get_header(headers, 'Subject') or '(No Subject)'
            sender_raw = _get_header(headers, 'From') or 'Unknown'
            date = _get_header(headers, 'Date') or ''
            auth_results = _get_header(headers, 'Authentication-Results') or ''
            spf_header = _get_header(headers, 'Received-SPF') or ''

            display_name, sender_email = _parse_sender(sender_raw)
            auth_checks = _parse_auth_headers(auth_results, spf_header)

            mail_list.append({
                'id': msg['id'],
                'sender': sender_raw,
                'display_name': display_name,
                'sender_email': sender_email,
                'subject': subject,
                'date': _format_date(date),
                'auth_checks': auth_checks,
                'snippet': m_data.get('snippet', ''),
                'sts_score': 'TBD',
                'mii_score': None,
                'risk_level': None
            })

        return mail_list

    except Exception as e:
        print(f"[CPIE] Gmail fetch error: {e}")
        return []


def fetch_full_email(service, email_id):
    try:
        m_data = service.users().messages().get(
            userId='me',
            id=email_id,
            format='full'
        ).execute()

        headers = m_data.get('payload', {}).get('headers', [])
        subject = _get_header(headers, 'Subject') or '(No Subject)'
        sender_raw = _get_header(headers, 'From') or 'Unknown'
        date = _get_header(headers, 'Date') or ''
        auth_results = _get_header(headers, 'Authentication-Results') or ''
        spf_header = _get_header(headers, 'Received-SPF') or ''

        display_name, sender_email = _parse_sender(sender_raw)
        auth_checks = _parse_auth_headers(auth_results, spf_header)

        # FIXED: Pass depth=0 to prevent infinite recursion on nested emails
        body_html, body_plain, image_attachments = _extract_body(
            m_data.get('payload', {}), service, email_id, depth=0
        )

        if body_html:
            final_body = body_html
        elif body_plain:
            final_body = ('<pre style="white-space:pre-wrap;font-family:inherit;font-size:14px;">'
                          + _escape_html(body_plain) + '</pre>')
        else:
            final_body = '<p style="color:#5f6368">No email body available.</p>'

        return {
            'id': email_id,
            'subject': subject,
            'sender': sender_raw,
            'display_name': display_name,
            'sender_email': sender_email,
            'date': _format_date(date),
            'body': final_body,
            'body_plain': body_plain,
            'auth_checks': auth_checks,
            'images': image_attachments,
            'snippet': m_data.get('snippet', '')
        }

    except Exception as e:
        print(f"[CPIE] Full email fetch error: {e}")
        return {
            'id': email_id,
            'subject': 'Error loading email',
            'sender': 'Unknown',
            'display_name': '',
            'sender_email': '',
            'date': '',
            'body': f'<p style="color:red">Failed to load: {str(e)}</p>',
            'body_plain': '',
            'auth_checks': {},
            'images': [],
            'snippet': ''
        }


# ── Helpers ──────────────────────────────────────────────────

def _get_header(headers, name):
    for h in headers:
        if h.get('name', '').lower() == name.lower():
            return h.get('value', '')
    return None


def _parse_sender(sender_raw):
    match = re.match(r'^(.*?)\s*<([^>]+)>', sender_raw)
    if match:
        return match.group(1).strip().strip('"'), match.group(2).strip()
    return sender_raw, sender_raw


def _format_date(date_str):
    if not date_str:
        return ''
    try:
        parts = date_str.split(',')
        return parts[1].strip()[:15] if len(parts) > 1 else date_str[:15]
    except Exception:
        return date_str[:20]


def _parse_auth_headers(auth_results, spf_header):
    checks = {
        'spf': 'unknown',
        'dkim': 'unknown',
        'dmarc': 'unknown',
        'display_name_mismatch': False
    }
    text = (auth_results + ' ' + spf_header).lower()
    checks['spf'] = ('pass' if 'spf=pass' in text
                     else 'fail' if ('spf=fail' in text or 'spf=softfail' in text)
                     else 'unknown')
    checks['dkim'] = ('pass' if 'dkim=pass' in text
                      else 'fail' if 'dkim=fail' in text
                      else 'unknown')
    checks['dmarc'] = ('pass' if 'dmarc=pass' in text
                       else 'fail' if 'dmarc=fail' in text
                       else 'unknown')
    return checks


def _extract_body(payload, service, email_id, depth=0):
    """
    FIXED: Added depth limit to prevent infinite recursion
    on complex nested multipart emails.
    """
    MAX_DEPTH = 10
    if depth > MAX_DEPTH:
        return '', '', []

    html_body = ''
    plain_body = ''
    images = []

    mime_type = payload.get('mimeType', '')
    parts = payload.get('parts', [])
    body_data = payload.get('body', {})

    if mime_type == 'text/html':
        raw = body_data.get('data', '')
        if raw:
            html_body = _decode_base64(raw)
    elif mime_type == 'text/plain':
        raw = body_data.get('data', '')
        if raw:
            plain_body = _decode_base64(raw)
    elif mime_type.startswith('image/'):
        attachment_id = body_data.get('attachmentId', '')
        if attachment_id:
            images.append({'attachment_id': attachment_id, 'mime_type': mime_type})

    for part in parts:
        sub_html, sub_plain, sub_images = _extract_body(
            part, service, email_id, depth=depth + 1
        )
        html_body = html_body or sub_html
        plain_body = plain_body or sub_plain
        images.extend(sub_images)

    return html_body, plain_body, images


def _decode_base64(data):
    """
    FIXED: Proper padding calculation instead of blindly adding ==
    Gmail strips padding so we must calculate exact missing bytes.
    """
    try:
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
    except Exception:
        return ''


def _escape_html(text):
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;'))