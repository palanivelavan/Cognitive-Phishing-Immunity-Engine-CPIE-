from core.sts_engine import calculate_sts
from core.nlp_engine import analyze_text
from core.ocr_engine import analyze_images
from core.url_engine import analyze_urls


def analyze_email(email_data, gmail_service=None):
    """
    Main CPIE detection pipeline.
    
    Input: email_data dict (from gmail_utils)
    Output: report dict ready for templates
    """

    report = {
        'sts_score': 100,
        'sts_level': 'LOW',
        'sts_reasons': [],
        'mii_score': 0,
        'risk_level': 'LOW',
        'flagged_phrases': [],
        'suspicious_urls': [],
        'analysis_notes': [],
        'auth_checks': email_data.get('headers', {}),
        'categories_found': []
    }

    # ── TIER 1: Sender Trust Score ────────────────────────
    sts_result = calculate_sts(email_data)
    report['sts_score'] = sts_result['score']
    report['sts_level'] = sts_result['level']
    report['sts_reasons'] = sts_result['reasons']
    report['auth_checks'] = email_data.get('headers', {})

    if sts_result['reasons']:
        report['analysis_notes'].extend(sts_result['reasons'])

    # ── If STS is HIGH (trusted) — stop here ─────────────
    if sts_result['level'] == 'LOW' and sts_result['score'] >= 75:
        report['risk_level'] = 'LOW'
        report['analysis_notes'].insert(0, "Sender passed all trust checks. No deep scan required.")
        return report

    # ── TIER 2: Deep Content Analysis ────────────────────
    report['analysis_notes'].insert(0,
        f"Sender trust score is {sts_result['score']}/100 — deep content analysis triggered."
    )

    body = email_data.get('body_plain', '') or email_data.get('body', '')
    subject = email_data.get('subject', '')
    full_text = subject + ' ' + body

    # NLP Analysis
    nlp_result = analyze_text(full_text)
    report['flagged_phrases'].extend(nlp_result.get('flagged_phrases', []))
    report['categories_found'].extend(nlp_result.get('categories_found', []))
    if nlp_result.get('nlp_notes'):
        report['analysis_notes'].extend(nlp_result['nlp_notes'])

    # URL Analysis
    url_result = analyze_urls(body)
    report['suspicious_urls'].extend(url_result.get('suspicious_urls', []))
    if url_result.get('url_notes'):
        report['analysis_notes'].extend(url_result['url_notes'])

    # OCR Analysis (only if images present)
    ocr_mii = 0  # CRITICAL FIX: Initialize here
    if email_data.get('images') and gmail_service:
        try:
            ocr_result = analyze_images(
                email_data['images'], gmail_service,
                email_data.get('id', '')
            )
            report['flagged_phrases'].extend(ocr_result.get('ocr_findings', []))
            if ocr_result.get('ocr_notes'):
                report['analysis_notes'].extend(ocr_result['ocr_notes'])
            ocr_mii = ocr_result.get('mii_contribution', 0)
        except Exception as e:
            print(f"[CPIE] OCR Error in detector: {e}")
            report['analysis_notes'].append("Failed to scan images for text.")

    # ── Calculate Final MII Score ─────────────────────────
    mii = (
        nlp_result.get('mii_contribution', 0) +
        url_result.get('mii_contribution', 0) +
        ocr_mii
    )
    report['mii_score'] = min(100, mii)

    # ── Final Risk Level ──────────────────────────────────
    if report['mii_score'] >= 60 or sts_result['score'] < 30:
        report['risk_level'] = 'HIGH'
    elif report['mii_score'] >= 30 or sts_result['score'] < 60:
        report['risk_level'] = 'MEDIUM'
    else:
        report['risk_level'] = 'LOW'

    # Summary note
    if report['flagged_phrases']:
        unique_categories = len(set(p.get('category') for p in report['flagged_phrases'] if p.get('category')))
        report['analysis_notes'].insert(0,
            f"Detected {len(report['flagged_phrases'])} manipulation pattern(s) across "
            f"{unique_categories} tactic categories."
        )

    return report