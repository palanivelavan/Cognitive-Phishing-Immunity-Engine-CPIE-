import re
import spacy

# Load spaCy model
try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    nlp = None
    print("[CPIE] spaCy model not loaded. Run: python -m spacy download en_core_web_sm")


# ── Manipulation pattern categories ──────────────────────
# Each entry: (regex_pattern, category, severity, explanation_template)

MANIPULATION_PATTERNS = [

    # ── URGENCY / DEADLINE ────────────────────────────────
    (r'\b(act now|immediate action|immediately|urgent|urgently|right away|'
     r'last chance|final notice|expire[sd]?|expiring|deadline|'
     r'within \d+ hour|within \d+ day|before it.?s too late|limited time)\b',
     'urgency', 'HIGH',
     'Creates artificial time pressure to prevent the recipient from thinking critically.'),

    # ── FEAR / THREAT ────────────────────────────────────
    (r'\b(suspend(ed)?|terminat(ed|ion)|block(ed)?|restrict(ed)?|'
     r'account.{0,20}(closed|disabled|locked|frozen)|'
     r'legal action|law enforcement|arrest|prosecut|penalty|fine|'
     r'unauthori[sz]ed access|breach|compromis(ed)?|hacked|'
     r'suspicious (activity|login|sign.?in))\b',
     'threat', 'HIGH',
     'Uses fear of account loss or legal consequences to override rational judgment.'),

    # ── AUTHORITY IMPERSONATION ───────────────────────────
    (r'\b(official notice|official communication|on behalf of|'
     r'government|irs|income tax|bank notice|rbi|sebi|'
     r'paypal security|amazon security|apple support|'
     r'microsoft support|google security|it department|'
     r'human resources|hr department|ceo|director|management)\b',
     'authority', 'MEDIUM',
     'Impersonates a trusted authority figure or institution to gain compliance.'),

    # ── REWARD / PRIZE TRAP ───────────────────────────────
    (r'\b(you.?ve (won|been selected|been chosen)|congratulations|'
     r'winner|prize|reward|gift card|free (iphone|ipad|laptop|cash)|'
     r'claim your|you are eligible|exclusive offer|'
     r'lucky (winner|draw|customer)|selected for)\b',
     'reward_trap', 'MEDIUM',
     'Uses a fabricated reward to lure the recipient into taking action.'),

    # ── CREDENTIAL HARVESTING ─────────────────────────────
    (r'\b(verify your (account|identity|email|password|details)|'
     r'confirm your (account|identity|information|password)|'
     r'update your (billing|payment|card|account)|'
     r'enter your (password|credentials|details|otp|pin)|'
     r'login to (confirm|verify|update)|'
     r'click (here|below|the link) to (verify|confirm|access|login))\b',
     'credential_harvest', 'HIGH',
     'Attempts to trick the recipient into entering their credentials on a fraudulent page.'),

    # ── SECRECY / ISOLATION ───────────────────────────────
    (r'\b(do not (share|forward|tell|disclose)|keep this (confidential|private|secret)|'
     r'do not reply to this email|contact us directly|'
     r'this is a private (message|communication)|for your eyes only)\b',
     'secrecy', 'MEDIUM',
     'Tries to isolate the recipient from seeking help or verification from others.'),

    # ── FAKE INVOICE / PAYMENT ────────────────────────────
    (r'\b(invoice (attached|enclosed|#\d+)|payment (due|overdue|pending|required)|'
     r'order (confirmation|has been placed|#\d+)|'
     r'your (subscription|membership) (has been|will be) (charged|renewed|billed)|'
     r'refund (available|pending|issued)|'
     r'transaction (failed|declined|requires attention))\b',
     'fake_invoice', 'HIGH',
     'Fabricates a financial transaction to create urgency or extract payment.'),

    # ── SOCIAL PROOF / MANIPULATION ──────────────────────
    (r'\b(thousands of (users|customers|people)|most (users|customers) (have|already)|'
     r'everyone is (using|doing)|don.?t miss out|'
     r'as (previously|already) (mentioned|notified|informed))\b',
     'social_proof', 'LOW',
     'Uses false social proof to normalize compliance with the request.'),
]

# Category display names
CATEGORY_LABELS = {
    'urgency': 'Urgency Tactic',
    'threat': 'Fear / Threat',
    'authority': 'Authority Impersonation',
    'reward_trap': 'Reward Trap',
    'credential_harvest': 'Credential Harvesting',
    'secrecy': 'Secrecy / Isolation',
    'fake_invoice': 'Fake Invoice / Payment',
    'social_proof': 'Social Proof Manipulation'
}

SEVERITY_WEIGHTS = {'HIGH': 20, 'MEDIUM': 12, 'LOW': 6}


def analyze_text(text):
    """
    Returns:
      {
        'mii_contribution': int,
        'flagged_phrases': [
          { 'text': str, 'category': str, 'severity': str, 'reason': str,
            'start': int, 'end': int }
        ],
        'categories_found': [str],
        'nlp_notes': [str]
      }
    """
    if not text:
        return _empty_result()

    clean_text = _clean_text(text)
    text_lower = clean_text.lower()

    flagged = []
    seen_spans = []
    total_weight = 0
    categories_found = set()

    for pattern, category, severity, explanation in MANIPULATION_PATTERNS:
        for match in re.finditer(pattern, text_lower, re.IGNORECASE):
            start, end = match.start(), match.end()

            # Avoid overlapping highlights
            if _overlaps(start, end, seen_spans):
                continue

            matched_original = clean_text[start:end]

            # Expand to full sentence for context
            sentence = _get_sentence_context(clean_text, start, end)

            flagged.append({
                'text': matched_original,
                'sentence': sentence,
                'category': CATEGORY_LABELS.get(category, category),
                'severity': severity,
                'reason': explanation,
                'start': start,
                'end': end
            })

            seen_spans.append((start, end))
            total_weight += SEVERITY_WEIGHTS[severity]
            categories_found.add(category)

    # NLP-based entity checks using spaCy
    nlp_notes = []
    if nlp and clean_text:
        try:
            doc = nlp(clean_text[:5000])  # Limit for performance

            # Detect suspicious money mentions
            money_ents = [ent.text for ent in doc.ents if ent.label_ == 'MONEY']
            if money_ents:
                nlp_notes.append(f"Financial amounts mentioned: {', '.join(money_ents[:3])} — common in payment scams.")
                total_weight += 8

            # Detect org impersonation
            org_ents = [ent.text for ent in doc.ents if ent.label_ == 'ORG']
            suspicious_orgs = [o for o in org_ents if _is_suspicious_org_mention(o, clean_text)]
            if suspicious_orgs:
                nlp_notes.append(f"Organization names used in suspicious context: {', '.join(suspicious_orgs[:3])}.")
                total_weight += 10

        except Exception as e:
            print(f"[CPIE] spaCy error: {e}")

    # MII contribution: cap at 60 from NLP alone (URL engine adds the rest)
    mii_contribution = min(60, total_weight)

    return {
        'mii_contribution': mii_contribution,
        'flagged_phrases': flagged,
        'categories_found': list(categories_found),
        'nlp_notes': nlp_notes
    }


def _clean_text(html_or_plain):
    """Strip HTML tags to get plain text for NLP analysis."""
    text = re.sub(r'<[^>]+>', ' ', html_or_plain)
    text = re.sub(r'&nbsp;', ' ', text)
    text = re.sub(r'&amp;', '&', text)
    text = re.sub(r'&lt;', '<', text)
    text = re.sub(r'&gt;', '>', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def _get_sentence_context(text, start, end):
    """Return the sentence containing the matched phrase."""
    # Find sentence boundaries
    sentence_start = max(0, text.rfind('.', 0, start) + 1)
    period_end = text.find('.', end)
    sentence_end = period_end if period_end != -1 else len(text)
    sentence = text[sentence_start:sentence_end].strip()
    return sentence[:200]  # Cap length


def _overlaps(start, end, seen_spans):
    for s, e in seen_spans:
        if start < e and end > s:
            return True
    return False


def _is_suspicious_org_mention(org_name, text):
    """Check if an org name is used in a manipulative sentence context."""
    text_lower = text.lower()
    org_lower = org_name.lower()
    idx = text_lower.find(org_lower)
    if idx == -1:
        return False
    context = text_lower[max(0, idx - 50):idx + 100]
    suspicious_verbs = ['verify', 'confirm', 'suspend', 'block', 'click', 'update', 'login', 'action']
    return any(v in context for v in suspicious_verbs)


def _empty_result():
    return {
        'mii_contribution': 0,
        'flagged_phrases': [],
        'categories_found': [],
        'nlp_notes': []
    }