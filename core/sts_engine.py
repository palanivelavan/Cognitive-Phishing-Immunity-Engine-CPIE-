import re
import socket


# ── Known trusted domains (expand as needed) ──────────────
TRUSTED_DOMAINS = {
    'gmail.com', 'google.com', 'yahoo.com', 'outlook.com',
    'hotmail.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'paypal.com', 'linkedin.com', 'github.com', 'twitter.com',
    'facebook.com', 'instagram.com', 'netflix.com', 'spotify.com',
    'jio.com', 'airtel.in', 'sbi.co.in', 'hdfcbank.com',
    'icicibank.com', 'infosys.com', 'tcs.com', 'wipro.com'
}

# ── Suspicious TLDs ──────────────────────────────────────
SUSPICIOUS_TLDS = {'.xyz', '.top', '.club', '.online', '.site',
                   '.click', '.win', '.loan', '.work', '.gq',
                   '.ml', '.cf', '.tk', '.pw', '.cc'}

# ── Homoglyph / typosquat patterns ───────────────────────
HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a',
    '@': 'a', '5': 's', '!': 'i', 'vv': 'w'
}


def calculate_sts(email_data):
    """
    Returns a dict:
      { 'score': 0-100, 'level': 'HIGH'/'MEDIUM'/'LOW', 'reasons': [...] }
    Higher STS = more trusted sender.
    """
    score = 100
    reasons = []

    sender = email_data.get('sender', '')
    display_name = email_data.get('display_name', '')
    subject = email_data.get('subject', '')
    headers = email_data.get('headers', {})

    sender_domain = _extract_domain(sender)

    # ── 1. SPF check ─────────────────────────────────────
    spf = headers.get('spf', 'unknown')
    if spf == 'fail':
        score -= 30
        reasons.append("SPF authentication failed — sender domain cannot be verified.")
    elif spf == 'unknown':
        score -= 10
        reasons.append("SPF record not found for sender domain.")

    # ── 2. DKIM check ────────────────────────────────────
    dkim = headers.get('dkim', 'unknown')
    if dkim == 'fail':
        score -= 25
        reasons.append("DKIM signature invalid — email may have been tampered.")
    elif dkim == 'unknown':
        score -= 8
        reasons.append("DKIM signature missing.")

    # ── 3. DMARC check ───────────────────────────────────
    dmarc = headers.get('dmarc', 'unknown')
    if dmarc == 'fail':
        score -= 20
        reasons.append("DMARC policy check failed.")
    elif dmarc == 'unknown':
        score -= 5

    # ── 4. Trusted domain bonus ──────────────────────────
    if sender_domain in TRUSTED_DOMAINS:
        score = min(score + 15, 100)
    
    # ── 5. Suspicious TLD ────────────────────────────────
    tld = '.' + sender_domain.split('.')[-1] if '.' in sender_domain else ''
    if tld in SUSPICIOUS_TLDS:
        score -= 25
        reasons.append(f"Sender uses a high-risk top-level domain ({tld}).")

    # ── 6. Typosquatting / homoglyph detection ───────────
    typo_target = _check_typosquat(sender_domain)
    if typo_target:
        score -= 30
        reasons.append(f"Domain '{sender_domain}' appears to impersonate '{typo_target}'.")

    # ── 7. Display name mismatch ─────────────────────────
    if display_name and sender_domain:
        dn_lower = display_name.lower()
        known_brands = list(TRUSTED_DOMAINS)
        for brand in known_brands:
            brand_name = brand.split('.')[0]
            if brand_name in dn_lower and brand_name not in sender_domain:
                score -= 25
                reasons.append(
                    f"Display name claims to be '{display_name}' but email comes from '{sender_domain}'."
                )
                headers['display_name_mismatch'] = True
                break

    # ── 8. Numeric/random subdomain ──────────────────────
    if re.search(r'\d{4,}', sender_domain):
        score -= 15
        reasons.append("Sender domain contains suspicious numeric pattern.")

    # ── 9. Very long domain ──────────────────────────────
    if len(sender_domain) > 40:
        score -= 10
        reasons.append("Sender domain is unusually long.")

    # ── 10. Excessive hyphens ────────────────────────────
    if sender_domain.count('-') >= 3:
        score -= 10
        reasons.append("Sender domain contains multiple hyphens — common in phishing domains.")

    score = max(0, min(100, score))

    if score >= 70:
        level = 'LOW'       # Trusted — no deep scan needed
    elif score >= 40:
        level = 'MEDIUM'    # Suspicious — run MII
    else:
        level = 'HIGH'      # Dangerous — full analysis

    return {
        'score': score,
        'level': level,
        'reasons': reasons,
        'sender_domain': sender_domain
    }


def _extract_domain(sender):
    match = re.search(r'@([\w.\-]+)', sender)
    return match.group(1).lower() if match else sender.lower()


def _check_typosquat(domain):
    """Check if domain looks like a typosquat of a known brand."""
    base = domain.split('.')[0] if '.' in domain else domain
    
    # Normalize homoglyphs
    normalized = base
    for fake, real in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(fake, real)

    for trusted in TRUSTED_DOMAINS:
        trusted_base = trusted.split('.')[0]
        # Exact match after normalization = homoglyph attack
        if normalized == trusted_base and base != trusted_base:
            return trusted
        # Levenshtein-like: check if one character off
        if trusted_base != base and _edit_distance(base, trusted_base) == 1:
            return trusted
    return None


def _edit_distance(s1, s2):
    """Simple edit distance for typosquat detection."""
    if abs(len(s1) - len(s2)) > 2:
        return 99
    if len(s1) > len(s2):
        s1, s2 = s2, s1
    distances = range(len(s1) + 1)
    for i2, c2 in enumerate(s2):
        distances_ = [i2 + 1]
        for i1, c1 in enumerate(s1):
            if c1 == c2:
                distances_.append(distances[i1])
            else:
                distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
        distances = distances_
    return distances[-1]