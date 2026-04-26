import re
import socket

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False


SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'online', 'site', 'click',
    'win', 'loan', 'work', 'gq', 'ml', 'cf', 'tk', 'pw', 'cc', 'info'
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'short.link', 'rebrand.ly', 'cutt.ly', 'is.gd', 'buff.ly'
}

TRUSTED_DOMAINS = {
    'google.com', 'gmail.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'paypal.com', 'linkedin.com', 'github.com',
    'twitter.com', 'facebook.com', 'instagram.com', 'netflix.com'
}

# Regex to extract URLs from text
URL_REGEX = re.compile(
    r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
    re.IGNORECASE
)


def analyze_urls(text):
    """
    Extracts and evaluates all URLs in the email body.
    
    Returns:
      { 'mii_contribution': int, 'suspicious_urls': [...], 'url_notes': [...] }
    """
    urls = _extract_urls(text)

    if not urls:
        return {'mii_contribution': 0, 'suspicious_urls': [], 'url_notes': []}

    suspicious = []
    total_score = 0
    url_notes = []

    for url in urls[:20]:  # Limit to 20 URLs per email
        result = _evaluate_url(url)
        if result['is_suspicious']:
            suspicious.append(result)
            total_score += result['risk_score']

    if len(urls) > 5:
        url_notes.append(
            f"Email contains {len(urls)} links — high link density is common in phishing emails."
        )
        total_score += 5

    if suspicious:
        url_notes.append(
            f"{len(suspicious)} of {len(urls)} links flagged as suspicious."
        )

    return {
        'mii_contribution': min(40, total_score),
        'suspicious_urls': suspicious,
        'url_notes': url_notes
    }


def _extract_urls(text):
    """Extract all URLs from HTML or plain text."""
    # Also extract href values from anchor tags
    href_urls = re.findall(r'href=["\']([^"\']+)["\']', text, re.IGNORECASE)
    body_urls = URL_REGEX.findall(text)
    all_urls = list(set(href_urls + body_urls))
    return [u for u in all_urls if len(u) > 10]


def _evaluate_url(url):
    """
    Evaluate a single URL for risk indicators.
    Returns a dict with risk details.
    """
    reasons = []
    risk_score = 0
    is_suspicious = False

    domain = _extract_domain(url)
    tld = _extract_tld(domain)

    # 1. URL shortener
    if domain in URL_SHORTENERS:
        reasons.append("Uses a URL shortener — destination is hidden from the recipient.")
        risk_score += 15
        is_suspicious = True

    # 2. Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Uses a high-risk domain extension (.{tld}).")
        risk_score += 15
        is_suspicious = True

    # 3. IP address instead of domain
    if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        reasons.append("URL uses a raw IP address — legitimate services use domain names.")
        risk_score += 25
        is_suspicious = True

    # 4. Trusted brand name inside a different domain (subdomain spoofing)
    for brand in TRUSTED_DOMAINS:
        brand_name = brand.split('.')[0]
        if brand_name in domain and not domain.endswith(brand):
            reasons.append(
                f"Contains '{brand_name}' in the URL but the actual domain is '{domain}' — "
                f"designed to look like {brand}."
            )
            risk_score += 30
            is_suspicious = True
            break

    # 5. Excessive subdomains
    subdomain_count = len(domain.split('.')) - 2
    if subdomain_count >= 3:
        reasons.append(f"URL has {subdomain_count} subdomains — used to bury the real domain.")
        risk_score += 10
        is_suspicious = True

    # 6. Very long URL
    if len(url) > 200:
        reasons.append("Unusually long URL — often used to confuse or hide malicious destination.")
        risk_score += 8
        is_suspicious = True

    # 7. Suspicious keywords in URL path
    path_lower = url.lower()
    suspicious_keywords = ['login', 'signin', 'verify', 'account', 'secure',
                           'update', 'confirm', 'banking', 'password', 'credential']
    found_keywords = [k for k in suspicious_keywords if k in path_lower]
    if found_keywords and domain not in TRUSTED_DOMAINS:
        reasons.append(
            f"URL path contains sensitive keywords ({', '.join(found_keywords[:3])}) "
            f"on an untrusted domain."
        )
        risk_score += 15
        is_suspicious = True

    # 8. Punycode / internationalized domain
    if 'xn--' in domain:
        reasons.append("Internationalized domain (punycode) — visually mimics legitimate domains.")
        risk_score += 20
        is_suspicious = True

    return {
        'url': url[:100],
        'domain': domain,
        'is_suspicious': is_suspicious,
        'risk_score': min(risk_score, 40),
        'reason': ' | '.join(reasons) if reasons else 'Low risk'
    }


def _extract_domain(url):
    try:
        url = url.replace('www.', '')
        match = re.search(r'https?://([^/?\s]+)', url)
        if match:
            return match.group(1).lower().split(':')[0]
        match = re.search(r'([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', url)
        return match.group(1).lower() if match else url.lower()
    except Exception:
        return url.lower()


def _extract_tld(domain):
    parts = domain.split('.')
    return parts[-1] if parts else ''