import os
import json
from flask import Flask, redirect, request, session, url_for, render_template
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from config import Config
from services.gmail_utils import get_gmail_service, fetch_inbox_metadata, fetch_full_email
from core.detector import analyze_email
from protection.annotator import annotate_email_body

# Moved to top level to prevent import loop crashes during dashboard rendering
from core.sts_engine import calculate_sts

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

def get_service():
    if 'credentials' not in session:
        return None
    try:
        creds_data = session['credentials']
        creds = Credentials(
            token=creds_data.get('token'),
            refresh_token=creds_data.get('refresh_token'),
            token_uri=creds_data.get('token_uri', 'https://oauth2.googleapis.com/token'),
            client_id=creds_data.get('client_id'),
            client_secret=creds_data.get('client_secret'),
            scopes=creds_data.get('scopes')
        )
        return get_gmail_service(creds)
    except Exception as e:
        print(f"[CPIE] get_service error: {e}")
        return None

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/login')
def login():
    with open(Config.CLIENT_SECRETS_FILE) as f:
        secrets = json.load(f)
    client_info = secrets.get('web') or secrets.get('installed')
    import urllib.parse
    params = {
        'client_id': client_info['client_id'],
        'redirect_uri': 'http://127.0.0.1:5000/callback',
        'response_type': 'code',
        'scope': ' '.join(Config.SCOPES),
        'access_type': 'offline',
        'prompt': 'consent'
    }
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urllib.parse.urlencode(params)
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return redirect(url_for('index'))
    with open(Config.CLIENT_SECRETS_FILE) as f:
        secrets = json.load(f)
    client_info = secrets.get('web') or secrets.get('installed')
    import requests as req
    token_response = req.post(
        'https://oauth2.googleapis.com/token',
        data={
            'code': code,
            'client_id': client_info['client_id'],
            'client_secret': client_info['client_secret'],
            'redirect_uri': 'http://127.0.0.1:5000/callback',
            'grant_type': 'authorization_code'
        }
    )
    token_data = token_response.json()
    if 'error' in token_data:
        return f"Login failed: {token_data.get('error_description', token_data['error'])}", 400
    session['credentials'] = {
        'token': token_data.get('access_token'),
        'refresh_token': token_data.get('refresh_token'),
        'token_uri': 'https://oauth2.googleapis.com/token',
        'client_id': client_info['client_id'],
        'client_secret': client_info['client_secret'],
        'scopes': Config.SCOPES
    }
    try:
        user_info_response = req.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f"Bearer {token_data.get('access_token')}"}
        )
        user_info = user_info_response.json()
        session['user_email'] = user_info.get('email', '')
    except Exception as e:
        print(f"[CPIE] User info error: {e}")
        session['user_email'] = ''
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'credentials' not in session:
        return redirect(url_for('index'))
    svc = get_service()
    if not svc:
        return redirect(url_for('index'))
    raw_emails = fetch_inbox_metadata(svc, max_results=20)
    processed = []
    for em in raw_emails:
        try:
            email_data = {
                'sender': em.get('sender', ''),
                'display_name': em.get('display_name', ''),
                'subject': em.get('subject', ''),
                'body': '',
                'body_plain': '',
                'headers': em.get('auth_checks', {}),
                'images': []
            }
            sts = calculate_sts(email_data)
            em['sts_score'] = sts['score']
            em['sts_level'] = sts['level']
            em['risk_level'] = sts['level']
            em['mii_score'] = None
        except Exception as e:
            print(f"[CPIE] STS error: {e}")
            em['sts_score'] = 'TBD'
            em['sts_level'] = 'UNKNOWN'
            em['risk_level'] = 'UNKNOWN'
        processed.append(em)
    return render_template('dashboard.html',
                           emails=processed,
                           user_email=session.get('user_email', ''))

@app.route('/email/<email_id>')
def email_view(email_id):
    if 'credentials' not in session:
        return redirect(url_for('index'))
    svc = get_service()
    if not svc:
        return redirect(url_for('index'))
    email = fetch_full_email(svc, email_id)
    email_data = {
        'sender': email.get('sender', ''),
        'display_name': email.get('display_name', ''),
        'subject': email.get('subject', ''),
        'body': email.get('body', ''),
        'body_plain': email.get('body_plain', ''),
        'headers': email.get('auth_checks', {}),
        'images': email.get('images', []),
        'id': email_id
    }
    report = analyze_email(email_data, gmail_service=svc)
    annotated_body = annotate_email_body(
        email.get('body', ''),
        email.get('body_plain', ''),
        report.get('flagged_phrases', []),
        report.get('suspicious_urls', [])
    )
    email['annotated_body'] = annotated_body
    return render_template('email_view.html', email=email, report=report)

@app.route('/sandbox/<email_id>')
def sandbox(email_id):
    if 'credentials' not in session:
        return redirect(url_for('index'))
    return render_template('sandbox.html', email_id=email_id)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/debug')
def debug():
    return str(session.get('credentials', 'NO CREDS'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)