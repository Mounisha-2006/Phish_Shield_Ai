"""
attachment_analyzer.py
-----------------------
Static analysis of email attachments for phishing / malware indicators.

This does NOT execute or open files in any unsafe way — everything here is
static inspection (reading file structure / bytes), which is the same
approach used by real entry-level malware triage tools. No sandboxing or
code execution is performed.

Three layers of analysis:
  1. Filename / extension risk      - always runs, no dependencies
  2. Office macro detection         - requires `oletools` (pip install oletools)
  3. PDF suspicious object detection - requires `pypdf` (pip install pypdf)
"""

import os
import re

# ── 1. FILENAME / EXTENSION RISK ─────────────────────────────────────

DANGEROUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
    '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
    '.ps1', '.psm1', '.jar', '.msi', '.lnk', '.hta'
]

MACRO_EXTENSIONS = [
    '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.xlsb'
]

ARCHIVE_EXTENSIONS = ['.zip', '.rar', '.7z', '.iso', '.img']

SAFE_DOCUMENT_EXTENSIONS = [
    '.pdf', '.docx', '.xlsx', '.pptx', '.txt', '.csv',
    '.png', '.jpg', '.jpeg', '.gif'
]


def check_filename_risk(filename):
    """Inspect the filename/extension for common malware-delivery patterns.
    Returns a dict with a risk score (0-100) and a list of reasons."""
    reasons = []
    score = 0
    name_lower = filename.lower().strip()

    # Double extension trick, e.g. "invoice.pdf.exe"
    parts = name_lower.split('.')
    if len(parts) > 2:
        # check if any extension before the last one looks like a safe doc type
        inner_exts = ['.' + p for p in parts[1:-1]]
        if any(ext in SAFE_DOCUMENT_EXTENSIONS for ext in inner_exts):
            reasons.append(f"Double extension detected (disguised as document): {filename}")
            score += 50

    ext = os.path.splitext(name_lower)[1]

    if ext in DANGEROUS_EXTENSIONS:
        reasons.append(f"Dangerous executable/script extension: {ext}")
        score += 60

    if ext in MACRO_EXTENSIONS:
        reasons.append(f"Macro-enabled Office format: {ext}")
        score += 30

    if ext in ARCHIVE_EXTENSIONS:
        reasons.append(f"Archive file (contents not visible without extraction): {ext}")
        score += 15

    # Suspicious naming patterns often used in phishing campaigns
    suspicious_name_words = [
        'invoice', 'receipt', 'payment', 'urgent', 'overdue',
        'statement', 'refund', 'win', 'prize', 'free', 'unpaid'
    ]
    if any(w in name_lower for w in suspicious_name_words) and ext in (DANGEROUS_EXTENSIONS + MACRO_EXTENSIONS):
        reasons.append("Filename uses urgency/financial bait language combined with a risky extension")
        score += 15

    # Excessive spaces before extension, e.g. "invoice.pdf        .exe" (trick to hide real ext)
    if re.search(r'\.\w{2,5}\s{2,}\.\w{2,5}$', filename):
        reasons.append("Suspicious whitespace padding before final extension (hides real file type)")
        score += 40

    return {
        'filename': filename,
        'extension': ext,
        'risk_score': min(score, 100),
        'reasons': reasons
    }


# ── 2. OFFICE MACRO DETECTION (oletools) ─────────────────────────────

def check_office_macros(filepath):
    """Use oletools to detect VBA macros in Office files (.doc, .docm, .xls,
    .xlsm, .ppt, .pptm, etc). Macros are a very common real-world malware
    delivery method. Returns dict with has_macros, suspicious_keywords, error."""
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return {
            'supported': False,
            'has_macros': False,
            'suspicious_keywords': [],
            'error': 'oletools not installed (pip install oletools)'
        }

    try:
        vba_parser = VBA_Parser(filepath)
        if not vba_parser.detect_vba_macros():
            vba_parser.close()
            return {'supported': True, 'has_macros': False, 'suspicious_keywords': [], 'error': None}

        # Known suspicious VBA keywords/functions commonly used by malicious macros
        suspicious_vba_terms = [
            'Shell', 'WScript.Shell', 'CreateObject', 'AutoOpen', 'AutoExec',
            'Document_Open', 'Workbook_Open', 'powershell', 'cmd.exe',
            'URLDownloadToFile', 'Environ(', 'Chr(', 'StrReverse'
        ]
        found_terms = set()
        for (_, _, _, vba_code) in vba_parser.extract_macros():
            for term in suspicious_vba_terms:
                if term.lower() in vba_code.lower():
                    found_terms.add(term)

        vba_parser.close()
        return {
            'supported': True,
            'has_macros': True,
            'suspicious_keywords': sorted(found_terms),
            'error': None
        }
    except Exception as e:
        return {'supported': True, 'has_macros': False, 'suspicious_keywords': [], 'error': str(e)}


# ── 3. PDF SUSPICIOUS OBJECT DETECTION (pypdf) ───────────────────────

def check_pdf_objects(filepath):
    """Inspect a PDF's internal objects for indicators commonly seen in
    malicious PDFs: embedded JavaScript, auto-launch actions, embedded files.
    Returns dict with flags found."""
    try:
        from pypdf import PdfReader
    except ImportError:
        return {
            'supported': False,
            'has_javascript': False,
            'has_launch_action': False,
            'has_embedded_files': False,
            'error': 'pypdf not installed (pip install pypdf)'
        }

    try:
        reader = PdfReader(filepath)
        raw = b''
        with open(filepath, 'rb') as f:
            raw = f.read()

        has_js = b'/JavaScript' in raw or b'/JS' in raw
        has_launch = b'/Launch' in raw
        has_embedded = b'/EmbeddedFile' in raw

        return {
            'supported': True,
            'has_javascript': has_js,
            'has_launch_action': has_launch,
            'has_embedded_files': has_embedded,
            'page_count': len(reader.pages),
            'error': None
        }
    except Exception as e:
        return {
            'supported': True,
            'has_javascript': False,
            'has_launch_action': False,
            'has_embedded_files': False,
            'error': str(e)
        }


# ── MAIN ENTRY POINT ──────────────────────────────────────────────────

def analyze_attachment(filepath, original_filename=None):
    """
    Run full static analysis on a single attachment file already saved to disk.
    `filepath`: path to the file on disk (e.g. in a temp upload folder)
    `original_filename`: the filename as received (for extension/naming checks);
                          falls back to the basename of filepath if not given.

    Returns a dict combining all checks plus an overall threat_level/confidence
    in the same shape as analyze_email()'s result, so app.py can save_scan()
    it the same way.
    """
    filename = original_filename or os.path.basename(filepath)
    ext = os.path.splitext(filename.lower())[1]

    name_check = check_filename_risk(filename)
    score = name_check['risk_score']
    reasons = list(name_check['reasons'])

    macro_result = {'supported': False, 'has_macros': False, 'suspicious_keywords': []}
    pdf_result = {'supported': False, 'has_javascript': False, 'has_launch_action': False, 'has_embedded_files': False}

    if ext in MACRO_EXTENSIONS or ext in ['.doc', '.xls', '.ppt']:
        macro_result = check_office_macros(filepath)
        if macro_result.get('has_macros'):
            score += 25
            reasons.append("VBA macro code detected in document")
            if macro_result.get('suspicious_keywords'):
                score += 25
                reasons.append(
                    "Macro uses suspicious functions: " + ', '.join(macro_result['suspicious_keywords'])
                )

    if ext == '.pdf':
        pdf_result = check_pdf_objects(filepath)
        if pdf_result.get('has_javascript'):
            score += 30
            reasons.append("PDF contains embedded JavaScript")
        if pdf_result.get('has_launch_action'):
            score += 35
            reasons.append("PDF contains an auto-launch action")
        if pdf_result.get('has_embedded_files'):
            score += 20
            reasons.append("PDF contains embedded files")

    score = min(score, 100)
    if score >= 60:
        threat_level = "HIGH"
    elif score >= 30:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    if not reasons:
        reasons.append("No suspicious indicators found in static analysis")

    return {
        "filename": filename,
        "threat_level": threat_level,
        "confidence": round(score, 2),
        "reasons": reasons,
        "filename_check": name_check,
        "macro_check": macro_result,
        "pdf_check": pdf_result
    }


if __name__ == '__main__':
    print("Testing attachment analyzer (filename-risk logic only, no real files needed)...\n")
    test_names = [
        "invoice.pdf",
        "invoice.pdf.exe",
        "salary_slip.docm",
        "report.docx",
        "Urgent_Refund_Form.exe",
        "photo.jpg",
        "archive.zip",
    ]
    for name in test_names:
        result = check_filename_risk(name)
        print(f"{name:30} risk={result['risk_score']:3}  reasons={result['reasons']}")
