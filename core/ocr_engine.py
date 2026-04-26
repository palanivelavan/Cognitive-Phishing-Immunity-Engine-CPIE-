import re
import base64
import os
import tempfile

try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False
    print("[CPIE] pytesseract/PIL not available. OCR disabled.")


def analyze_images(image_list, gmail_service=None, email_id=None):
    if not OCR_AVAILABLE or not image_list:
        return {'mii_contribution': 0, 'ocr_findings': [], 'ocr_notes': []}

    all_text = ''
    ocr_notes = []

    for img_info in image_list:
        attachment_id = img_info.get('attachment_id', '')
        if not attachment_id or not gmail_service:
            continue
        try:
            attachment = gmail_service.users().messages().attachments().get(
                userId='me',
                messageId=email_id,
                id=attachment_id
            ).execute()

            img_data = base64.urlsafe_b64decode(
                attachment.get('data', '') + '=='
            )

            # FIXED: Close the temp file before PIL opens it (Windows fix)
            tmp_path = None
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
                tmp.write(img_data)
                tmp_path = tmp.name
            # File is now closed — PIL can open it safely on Windows

            img = Image.open(tmp_path)
            extracted = pytesseract.image_to_string(img)
            img.close()
            os.unlink(tmp_path)

            if extracted.strip():
                all_text += ' ' + extracted
                ocr_notes.append(
                    f"Text extracted from embedded image ({len(extracted)} chars)."
                )

        except Exception as e:
            print(f"[CPIE] OCR error: {e}")
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

    if not all_text.strip():
        return {'mii_contribution': 0, 'ocr_findings': [], 'ocr_notes': []}

    from core.nlp_engine import analyze_text
    nlp_result = analyze_text(all_text)

    ocr_findings = []
    for phrase in nlp_result['flagged_phrases']:
        phrase['source'] = 'IMAGE (OCR)'
        ocr_findings.append(phrase)

    if ocr_findings:
        ocr_notes.append(
            f"Found {len(ocr_findings)} manipulation pattern(s) hidden inside email images — "
            "a common technique to bypass text-based filters."
        )

    return {
        'mii_contribution': min(30, nlp_result['mii_contribution']),
        'ocr_findings': ocr_findings,
        'ocr_notes': ocr_notes + nlp_result['nlp_notes']
    }