import os

class Config:
    SECRET_KEY = 'cpie_dev_master_key_7788'
    CLIENT_SECRETS_FILE = "client_secrets.json"
    SCOPES = [
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/userinfo.email',
        'openid'
    ]