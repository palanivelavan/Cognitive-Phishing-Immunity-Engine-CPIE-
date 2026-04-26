import re
import html as html_module

def annotate_email_body(body_html, body_plain, flagged_phrases, suspicious_urls):
    """
    Main entry point. Prioritizes HTML body to keep original formatting
    but falls back to plain text if necessary.
    """
    # Use HTML if available, otherwise wrap plain text using your helper
    content = body_html if body_html else _plain_to_html(body_plain)
    
    if not flagged_phrases and not suspicious_urls:
        return content

    # 1. Annotate Phrases (Manipulative Patterns)
    # Sort by length descending to match longest phrases first
    sorted_phrases = sorted(flagged_phrases, key=lambda x: len(x.get('text', '')), reverse=True)
    
    for phrase in sorted_phrases:
        p_text = phrase.get('text', '').strip()
        if not p_text or len(p_text) < 3: continue

        severity = phrase.get('severity', 'MEDIUM').lower()
        category = phrase.get('category', 'Suspicious')
        reason = phrase.get('reason', '')

        # CRITICAL REGEX: Matches the text ONLY if it is not inside an HTML tag attribute
        # This prevents breaking <img src="..."> or <a href="..."> tags
        pattern = re.compile(f"(?![^<]*>){re.escape(p_text)}", re.IGNORECASE)
        
        highlight_html = (
            f'<span class="cpie-highlight cpie-{severity}">'
            f'{html_module.escape(p_text)}'
            f'<span class="cpie-tooltip"><b>{html_module.escape(category)}:</b> {html_module.escape(reason)}</span>'
            f'</span>'
        )
        
        # Replace only the first occurrence to keep the UI clean
        content = pattern.sub(highlight_html, content, count=1)

    # 2. Annotate Suspicious URLs
    for url_info in suspicious_urls:
        url = url_info.get('url', '')
        reason = url_info.get('reason', 'Suspicious Link')
        if url and url in content:
            warning_wrapper = (
                f'<span class="cpie-url-flag" title="{html_module.escape(reason)}">'
                f'⚠️ {html_module.escape(url)}</span>'
            )
            # Use replace for direct URL matches
            content = content.replace(url, warning_wrapper)

    return content


def _plain_to_html(plain):
    if not plain:
        return ''
    safe = html_module.escape(plain)
    return f'<div style="font-size:14px;line-height:1.8;white-space:pre-wrap;font-family:Roboto,sans-serif;">{safe}</div>'

def _strip_html(html_text):
    if not html_text: return ''
    text = re.sub(r'<[^>]+>', ' ', html_text)
    return html_module.unescape(text).strip()