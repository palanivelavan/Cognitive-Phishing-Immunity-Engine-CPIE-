# Standard data contracts between all modules

def email_input_schema():
    return {
        "sender": "",
        "display_name": "",
        "subject": "",
        "body": "",
        "body_plain": "",
        "headers": {
            "spf": "unknown",
            "dkim": "unknown",
            "dmarc": "unknown",
            "display_name_mismatch": False
        },
        "images": []
    }

def report_schema():
    return {
        "sts_score": 0,
        "mii_score": 0,
        "risk_level": "LOW",
        "flagged_phrases": [],
        "suspicious_urls": [],
        "analysis_notes": [],
        "auth_checks": {}
    }