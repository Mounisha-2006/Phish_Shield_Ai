from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import pickle
import pandas as pd
import os
import sys
import tempfile
import uuid
from datetime import date, timedelta
from werkzeug.utils import secure_filename

sys.path.append(os.path.expanduser('~/phishshield/backend'))
sys.path.append(os.path.expanduser('~/phishshield/reports'))

from url_analyzer import extract_features, check_trusted, check_typosquatting, check_insecure_brand, is_valid_url, has_valid_extension, is_gibberish_domain, RESTRICTED_TRUST_TLDS
import tldextract
from explainability import explain_prediction
from email_analyzer import analyze_email, analyze_email_deep, analyze_email_with_attachments, get_recommendation
from clone_detector import detect_clone
from report_generator import generate_report

app = Flask(
    __name__,
    template_folder=os.path.expanduser('~/phishshield/frontend/templates'),
    static_folder=os.path.expanduser('~/phishshield/frontend/static')
)
app.secret_key = 'phishshield_secret_2026'

model_path = os.path.expanduser('~/phishshield/backend/models/url_model.pkl')
with open(model_path, 'rb') as f:
    url_model = pickle.load(f)

def init_db():
    conn = sqlite3.connect(os.path.expanduser('~/phishshield/users.db'))
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fname TEXT NOT NULL,
        lname TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT,
        scan_type TEXT,
        input_data TEXT,
        threat_level TEXT,
        confidence REAL,
        brand TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    # Migration: add 'brand' column if the table already existed from
    # before this feature was added, so existing databases don't break.
    try:
        conn.execute('ALTER TABLE scans ADD COLUMN brand TEXT')
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.commit()
    conn.close()

def get_db():
    return sqlite3.connect(os.path.expanduser('~/phishshield/users.db'))

def save_scan(user_email, scan_type, input_data, threat_level, confidence, brand=None):
    conn = get_db()
    conn.execute(
        'INSERT INTO scans (user_email, scan_type, input_data, threat_level, confidence, brand) VALUES (?,?,?,?,?,?)',
        (user_email, scan_type, input_data, threat_level, confidence, brand)
    )
    conn.commit()
    conn.close()

@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'])

@app.route('/signup', methods=['POST'])
def signup():
    data  = request.get_json()
    fname = data.get('fname', '')
    lname = data.get('lname', '')
    email = data.get('email', '')
    pwd   = data.get('password', '')
    if not fname or not email or not pwd:
        return jsonify({'success': False, 'message': 'All fields required'})
    hashed = generate_password_hash(pwd)
    try:
        conn = get_db()
        conn.execute(
            'INSERT INTO users (fname, lname, email, password) VALUES (?,?,?,?)',
            (fname, lname, email, hashed)
        )
        conn.commit()
        conn.close()
        session['user']  = email
        session['fname'] = fname
        return jsonify({'success': True, 'message': 'Account created!'})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Email already exists!'})

@app.route('/signin', methods=['POST'])
def signin():
    data  = request.get_json()
    email = data.get('email', '')
    pwd   = data.get('password', '')
    conn  = get_db()
    user  = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    conn.close()
    if user and check_password_hash(user[4], pwd):
        session['user']  = email
        session['fname'] = user[1]
        return jsonify({'success': True, 'message': 'Signed in!'})
    return jsonify({'success': False, 'message': 'Wrong email or password!'})
@app.route('/email-scanner')
def email_scanner():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('email_scanner.html', user=session['user'])

@app.route('/analytics/data')
def analytics_data():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    conn = get_db()
    user_email = session['user']

    # 1) Threat level breakdown (HIGH/MEDIUM/LOW counts)
    threat_rows = conn.execute(
        'SELECT threat_level, COUNT(*) FROM scans WHERE user_email=? GROUP BY threat_level',
        (user_email,)
    ).fetchall()
    threat_breakdown = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for level, count in threat_rows:
        if level in threat_breakdown:
            threat_breakdown[level] = count

    # 2) Scan type distribution (URL/Email/Clone counts)
    type_rows = conn.execute(
        'SELECT scan_type, COUNT(*) FROM scans WHERE user_email=? GROUP BY scan_type',
        (user_email,)
    ).fetchall()
    type_breakdown = {scan_type: count for scan_type, count in type_rows}

    # 3) Trend over time - scans per day, last 14 days
    trend_rows = conn.execute('''
        SELECT DATE(timestamp) as day,
               COUNT(*) as total,
               SUM(CASE WHEN threat_level='HIGH' THEN 1 ELSE 0 END) as high_count
        FROM scans
        WHERE user_email=? AND DATE(timestamp) >= DATE('now', '-14 days')
        GROUP BY DATE(timestamp)
        ORDER BY day ASC
    ''', (user_email,)).fetchall()
    trend = [{'day': row[0], 'total': row[1], 'high': row[2]} for row in trend_rows]

    # 4) Top targeted brands (from typosquatting/clone/insecure-protocol detections)
    brand_rows = conn.execute('''
        SELECT brand, COUNT(*) as count
        FROM scans
        WHERE user_email=? AND brand IS NOT NULL AND brand != ''
        GROUP BY brand
        ORDER BY count DESC
        LIMIT 10
    ''', (user_email,)).fetchall()
    top_brands = [{'brand': row[0], 'count': row[1]} for row in brand_rows]

    # 5) Summary numbers
    total_scans = sum(threat_breakdown.values())
    threats_found = threat_breakdown['HIGH'] + threat_breakdown['MEDIUM']

    # 6) Category breakdown for the overview "Threat breakdown" donut -
    #    crosses scan type with risk level so "Phishing URLs" only counts
    #    URL scans that actually came back HIGH/MEDIUM, not every URL ever
    #    scanned. "Safe" combines LOW-risk results across all scan types.
    category_rows = conn.execute('''
        SELECT scan_type,
               SUM(CASE WHEN threat_level IN ('HIGH','MEDIUM') THEN 1 ELSE 0 END) as risky,
               SUM(CASE WHEN threat_level='LOW' THEN 1 ELSE 0 END) as safe
        FROM scans
        WHERE user_email=?
        GROUP BY scan_type
    ''', (user_email,)).fetchall()
    category_breakdown = {'phishing_urls': 0, 'phishing_emails': 0, 'clone_sites': 0, 'safe': 0}
    for scan_type, risky, safe in category_rows:
        if scan_type == 'URL':
            category_breakdown['phishing_urls'] = risky or 0
        elif scan_type == 'Email':
            category_breakdown['phishing_emails'] = risky or 0
        elif scan_type == 'Clone':
            category_breakdown['clone_sites'] = risky or 0
        category_breakdown['safe'] += safe or 0

    # 7) Activity heatmap - last 49 days (7x7 grid, oldest first), zero-
    #    filled so a day with no scans still renders as a real "no
    #    activity" cell instead of shifting the grid or being skipped.
    heatmap_rows = conn.execute('''
        SELECT DATE(timestamp) as day,
               COUNT(*) as total,
               SUM(CASE WHEN threat_level='HIGH' THEN 1 ELSE 0 END) as high_count
        FROM scans
        WHERE user_email=? AND DATE(timestamp) >= DATE('now', '-48 days')
        GROUP BY DATE(timestamp)
    ''', (user_email,)).fetchall()
    heatmap_by_day = {row[0]: {'total': row[1], 'high': row[2] or 0} for row in heatmap_rows}
    heatmap = []
    for i in range(48, -1, -1):
        day_str = (date.today() - timedelta(days=i)).isoformat()
        d = heatmap_by_day.get(day_str, {'total': 0, 'high': 0})
        heatmap.append({'day': day_str, 'total': d['total'], 'high': d['high']})

    # 8) Today's counts for the "Blocked today / Safe today" stat cards
    today_row = conn.execute('''
        SELECT
            SUM(CASE WHEN threat_level='HIGH' THEN 1 ELSE 0 END) as blocked,
            SUM(CASE WHEN threat_level='LOW' THEN 1 ELSE 0 END) as safe
        FROM scans
        WHERE user_email=? AND DATE(timestamp) = DATE('now')
    ''', (user_email,)).fetchone()
    today_stats = {
        'blocked': today_row[0] or 0,
        'safe'   : today_row[1] or 0
    }

    conn.close()

    return jsonify({
        'total_scans'        : total_scans,
        'threats_found'      : threats_found,
        'threat_breakdown'   : threat_breakdown,
        'type_breakdown'     : type_breakdown,
        'category_breakdown' : category_breakdown,
        'heatmap'             : heatmap,
        'today'               : today_stats,
        'trend'              : trend,
        'top_brands'         : top_brands
    })

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/scan/url', methods=['POST'])
def scan_url():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({
            "valid"  : False,
            "url"    : url,
            "error"  : "empty_input",
            "message": "Please enter a URL to scan."
        })

    # 0) Validate the input is actually a well-formed URL FIRST — it must
    #    start with http:// or https:// and have a real, well-formed
    #    domain. Plain text like "go", "home", "hello" is rejected here
    #    too, with a clear error instead of silently running through the
    #    risk scoring pipeline (which used to produce a meaningless
    #    low-risk score for garbage input).
    valid, invalid_reason = is_valid_url(url)
    if not valid:
        return jsonify({
            "valid"  : False,
            "url"    : url,
            "error"  : invalid_reason,
            "message": "Invalid URL. Please enter a valid URL (e.g. https://example.com)."
        })

    # 1) Insecure protocol / impersonation check — a trusted brand domain
    #    (or close match) served over plain http:// instead of https://
    #    is a strong phishing signal, since the real site always forces
    #    HTTPS. This does NOT force every http:// URL to HIGH on its own
    #    (see url_analyzer.evaluate_link_risk / main() for that combined
    #    scoring) — it only fires here when the domain matches or closely
    #    resembles a known trusted brand.
    insecure, insecure_brand = check_insecure_brand(url)
    if insecure:
        # check_insecure_brand() fires in two different situations that
        # deserve different verdicts:
        #   - the domain IS the real trusted domain (e.g. google.com)
        #     served over plain http:// - insecure, but not an impostor.
        #   - the domain merely resembles/contains a brand name on a
        #     DIFFERENT domain (e.g. paypal.attacker-verify.tk) - a real
        #     impersonation attempt.
        # Only the second case should stay HIGH; the first is downgraded
        # to MEDIUM so a trusted domain over http isn't scored the same
        # as active brand impersonation.
        if check_trusted(url):
            threat_level = "MEDIUM"
            confidence   = 40.0
        else:
            threat_level = "HIGH"
            confidence   = 90.0
        save_scan(session['user'], 'URL', url, threat_level, confidence, brand=insecure_brand)
        return jsonify({
            "url"          : url,
            "is_phishing"  : threat_level == "HIGH",
            "threat_level" : threat_level,
            "confidence"   : confidence,
            "reason"       : "insecure_protocol",
            "impersonated_brand": insecure_brand if threat_level == "HIGH" else None
        })

    # 2) Extension check — the URL is well-formed (has http(s):// and a
    #    real domain), but if it doesn't end in a recognized, legitimate
    #    extension (.com, .in, .org, etc.) that's a strong phishing signal
    #    on its own (commonly-abused extensions like .xyz, .tk, .top, or
    #    made-up ones). Force HIGH risk rather than falling through to the
    #    ML model.
    if not has_valid_extension(url):
        threat_level = "HIGH"
        confidence   = 85.0
        save_scan(session['user'], 'URL', url, threat_level, confidence)
        return jsonify({
            "url"          : url,
            "is_phishing"  : True,
            "threat_level" : threat_level,
            "confidence"   : confidence,
            "reason"       : "invalid_extension"
        })

    # 3) Whitelist check — official trusted domains (already confirmed
    #    HTTPS by step 1) are always safe, skip the ML model entirely so
    #    they get a clean 0%.
    if check_trusted(url):
        threat_level = "LOW"
        confidence   = 0.0
        save_scan(session['user'], 'URL', url, threat_level, confidence)
        return jsonify({
            "url"          : url,
            "is_phishing"  : False,
            "threat_level" : threat_level,
            "confidence"   : confidence,
            "reason"       : "trusted_domain"
        })

    # 4) Typosquatting check — misspelled brand domains (g00gle, paypa1, etc.)
    #    are forced to HIGH risk regardless of what the ML model says.
    is_typo, brand, typo_word = check_typosquatting(url)
    if is_typo:
        threat_level = "HIGH"
        confidence   = 95.0
        save_scan(session['user'], 'URL', url, threat_level, confidence, brand=brand)
        return jsonify({
            "url"          : url,
            "is_phishing"  : True,
            "threat_level" : threat_level,
            "confidence"   : confidence,
            "reason"       : "typosquatting",
            "impersonated_brand": brand
        })

    # 4.5) Gibberish domain on a restricted TLD — a domain name that
    #    looks randomly generated (not a real word/name/brand) sitting on
    #    a RESTRICTED TLD (.edu, .gov, .mil, .ac.in, etc — TLDs that
    #    require real-world vetting to register, unlike .com/.xyz/etc)
    #    is very unlikely to be a legitimately registered institution.
    #    Force HIGH regardless of what the ML model would otherwise say,
    #    same as the typosquatting/insecure-brand checks above.
    ext = tldextract.extract(url)
    domain_part = ext.domain
    suffix_part = ext.suffix.lower()
    if is_gibberish_domain(domain_part) and suffix_part in RESTRICTED_TRUST_TLDS:
        threat_level = "HIGH"
        confidence   = 88.0
        save_scan(session['user'], 'URL', url, threat_level, confidence)
        return jsonify({
            "url"          : url,
            "is_phishing"  : True,
            "threat_level" : threat_level,
            "confidence"   : confidence,
            "reason"       : "gibberish_domain_restricted_tld"
        })

    # 5) Otherwise, fall back to the ML model for everything else.
    features     = extract_features(url)
    df           = pd.DataFrame([features])
    prediction   = url_model.predict(df)[0]
    probability  = url_model.predict_proba(df)[0][1]
    threat_level = "HIGH" if probability >= 0.7 else "MEDIUM" if probability >= 0.4 else "LOW"
    confidence   = round(probability * 100, 2)

    # A randomly-generated-looking domain name on an ORDINARY TLD (not
    # restricted enough to force HIGH above) is still a real, if weaker,
    # phishing signal that the model's feature set doesn't capture at
    # all — entropy/randomness was deliberately left out of
    # extract_features (see url_analyzer.py notes on why). Nudge the
    # verdict up one tier as a supporting signal rather than overriding
    # the model outright.
    if domain_part and is_gibberish_domain(domain_part) and threat_level != "HIGH":
        threat_level = "MEDIUM" if threat_level == "LOW" else "HIGH"
        confidence   = max(confidence, 55.0)

    save_scan(session['user'], 'URL', url, threat_level, confidence)

    # Explainability: show which features drove this specific prediction.
    # Wrapped in try/except so a SHAP failure never breaks the actual scan -
    # explanation is a bonus, not a required part of the result.
    explanation = []
    try:
        explanation = explain_prediction(url_model, df, top_n=5)
    except Exception as e:
        print(f"[explainability] Could not generate explanation: {e}")

    return jsonify({
        "url"          : url,
        "is_phishing"  : bool(prediction),
        "threat_level" : threat_level,
        "confidence"   : confidence,
        "reason"       : "ml_model",
        "explanation"  : explanation
    })

@app.route('/scan/email', methods=['POST'])
def scan_email():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    # Support both plain JSON (no attachment, backward compatible) and
    # multipart/form-data (when the user attaches a file from the dashboard).
    if request.content_type and 'multipart/form-data' in request.content_type:
        subject = request.form.get('subject', '')
        body    = request.form.get('body', '')
        uploaded_files = request.files.getlist('attachments')
    else:
        data    = request.get_json() or {}
        subject = data.get('subject', '')
        body    = data.get('body', '')
        uploaded_files = []

    attachment_paths = []
    saved_paths_to_cleanup = []
    if uploaded_files:
        upload_dir = os.path.join(tempfile.gettempdir(), 'phishshield_uploads')
        os.makedirs(upload_dir, exist_ok=True)
        for f in uploaded_files:
            if not f.filename:
                continue
            safe_name = f"{uuid.uuid4().hex}_{secure_filename(f.filename)}"
            save_path = os.path.join(upload_dir, safe_name)
            f.save(save_path)
            attachment_paths.append({
                'filepath': save_path,
                'original_filename': f.filename
            })
            saved_paths_to_cleanup.append(save_path)

    if attachment_paths:
        result = analyze_email_with_attachments(subject, body, attachment_paths)
    else:
        result = analyze_email(subject, body)

    # Clean up temp uploaded files after analysis — we don't need to keep them
    for p in saved_paths_to_cleanup:
        try:
            os.remove(p)
        except OSError:
            pass

    save_scan(session['user'], 'Email', subject, result['threat_level'], result['confidence'])
    return jsonify(result)

@app.route('/scan/clone', methods=['POST'])
def scan_clone():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    data   = request.get_json()
    url    = data.get('url', '').strip()
    result = detect_clone(url)
    save_scan(session['user'], 'Clone', url, result['threat_level'], result['confidence'], brand=result.get('impersonated_brand'))
    return jsonify(result)

@app.route('/history')
def history():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    conn  = get_db()
    scans = conn.execute(
        'SELECT scan_type, input_data, threat_level, confidence, timestamp FROM scans WHERE user_email=? ORDER BY timestamp DESC LIMIT 20',
        (session['user'],)
    ).fetchall()
    conn.close()
    result = []
    for s in scans:
        result.append({
            'type'         : s[0],
            'input'        : s[1],
            'threat_level' : s[2],
            'confidence'   : s[3],
            'time'         : s[4]
        })
    return jsonify(result)

@app.route('/download/report')
def download_report():
    if 'user' not in session:
        return redirect(url_for('login'))
    conn  = get_db()
    scans = conn.execute(
        'SELECT scan_type, input_data, threat_level, confidence, timestamp FROM scans WHERE user_email=? ORDER BY timestamp DESC LIMIT 20',
        (session['user'],)
    ).fetchall()
    conn.close()
    if not scans:
        return "No scans found! Please do some scans first.", 400
    scan_results = []
    for s in scans:
        scan_results.append({
            'type'         : s[0],
            'input'        : s[1],
            'threat_level' : s[2],
            'confidence'   : s[3],
            'time'         : s[4]
        })
    path = generate_report(
        scan_results=scan_results,
        user_email=session['user']
    )
    return send_file(
        path,
        as_attachment=True,
        download_name='PhishShield_Report.pdf'
    )

@app.route('/chat', methods=['POST'])
def chat():
    data    = request.get_json()
    message = data.get('message', '').lower().strip()

    def get_reply(msg):

        if 'your name' in msg or 'ur name' in msg or 'who are you' in msg or 'what are you' in msg:
            return "I am PhishShield AI Assistant! I am your personal cybersecurity helper built inside this project!"

        if 'what is phishing' in msg or 'phishing mean' in msg or 'about phishing' in msg or 'explain phishing' in msg or 'phishing kya' in msg:
            return "Phishing is a cyber attack where hackers send fake emails or create fake websites to steal your passwords and personal data. Example: A fake PayPal email asking you to verify your account. PhishShield AI detects these attacks automatically!"

        if 'url scan' in msg or 'scan url' in msg or 'url check' in msg or 'about url' in msg or 'url scanning' in msg or 'url detection' in msg or 'tell me about url' in msg:
            return "URL Scanning: I extract 25 features from your URL like length, HTTPS, domain age and suspicious keywords. A Random Forest ML model trained on 40000 URLs predicts if it is phishing or safe. You get HIGH, MEDIUM or LOW threat level with confidence score!"

        if 'email scan' in msg or 'scan email' in msg or 'email check' in msg or 'about email' in msg or 'email detection' in msg or 'tell me about email' in msg:
            return "Email Scanning: I analyze subject and body text. I look for urgency words like Urgent, Verify Now, Suspended. I check for suspicious links and AI writing patterns. You get a threat level with confidence score!"

        if 'clone' in msg or 'fake website' in msg or 'fake site' in msg or 'clone detect' in msg:
            return "Clone Detection: I fetch the suspicious website and check if the page title mentions a famous brand like PayPal or Google. If the domain does not match the real brand it is flagged as a cloned website!"

        if 'report' in msg or 'pdf' in msg or 'download' in msg:
            return "To download your PDF security report click the purple download button in the top right corner of your dashboard. The report shows all scan results with threat levels and security recommendations!"

        if 'machine learning' in msg or 'random forest' in msg or 'ml model' in msg or 'algorithm' in msg:
            return "I use a Random Forest Classifier trained on 40000 URLs from PhishTank dataset. It uses 25 features like URL length, special characters, domain age and entropy. The model achieves 84% accuracy!"

        if 'bert' in msg or 'nlp' in msg or 'natural language' in msg:
            return "BERT stands for Bidirectional Encoder Representations from Transformers. It is a Google AI model that reads sentences in both directions to understand the full meaning. It is used to detect AI-generated phishing emails!"

        if 'how to use' in msg or 'how do i' in msg or 'guide' in msg or 'tutorial' in msg or 'help me' in msg:
            return "How to use PhishShield AI: Step 1 - Enter a suspicious URL and click Analyze URL. Step 2 - Paste a suspicious email and click Analyze Email. Step 3 - Check a suspicious website using Clone Detector. Step 4 - Download your PDF report!"

        if 'technology' in msg or 'tech stack' in msg or 'built with' in msg or 'python' in msg or 'flask' in msg:
            return "PhishShield AI is built with Python for backend, Flask for web server, Scikit-learn for ML model, NLP for email analysis, BeautifulSoup for clone detection, SQLite for database and FPDF2 for PDF reports!"

        if 'accuracy' in msg or 'performance' in msg or 'how good' in msg or 'how accurate' in msg:
            return "PhishShield AI Performance: URL ML Model - 84% accuracy on 40000 URLs. Email NLP Analyzer - 94% confidence. Clone Detector - 89% confidence. All tested on real phishing datasets!"

        if 'tip' in msg or 'advice' in msg or 'stay safe' in msg or 'protect' in msg or 'safety' in msg:
            return "Top 5 Cyber Safety Tips: 1) Never click unknown links in emails. 2) Always check URL before logging in. 3) Enable 2-factor authentication. 4) Use strong unique passwords. 5) Always scan suspicious links with PhishShield AI!"

        if 'project' in msg or 'about this' in msg or 'what is this' in msg or 'phishshield' in msg:
            return "PhishShield AI is a Major Project built using Python. It is an AI-Driven Cyber Threat Detection System that detects phishing URLs, phishing emails and cloned websites using Machine Learning and NLP!"

        if 'who made' in msg or 'who built' in msg or 'developer' in msg or 'creator' in msg:
            return "PhishShield AI was built as a Major Python Project using Machine Learning and Natural Language Processing to solve the real-world problem of AI-generated phishing attacks!"

        if 'dark mode' in msg or 'theme' in msg or 'night mode' in msg:
            return "Dark mode and theme switching feature is coming soon to PhishShield AI dashboard! Stay tuned for updates!"

        if 'notification' in msg or 'alert' in msg or 'notify' in msg:
            return "PhishShield AI shows real-time alerts when a HIGH RISK threat is detected during scanning. Check the bell icon in the top right corner for all your notifications!"

        if 'thank' in msg or 'thanks' in msg or 'great' in msg or 'awesome' in msg or 'good job' in msg or 'nice' in msg:
            return "You are welcome! Stay safe online. Remember to always scan suspicious links before clicking. PhishShield AI is here to protect you 24/7!"

        if 'bye' in msg or 'goodbye' in msg or 'see you' in msg or 'good night' in msg or 'good morning' in msg:
            return "Goodbye! Stay cyber safe! Remember - Think before you click! PhishShield AI will always be here when you need protection!"

        if msg in ['hi','hello','hey','hii','helo','hai','hiya'] or msg.startswith('hi ') or msg.startswith('hello ') or msg.startswith('hey '):
            return "Hello! I am PhishShield AI Assistant. Ask me about phishing, URL scanning, email scanning, clone detection or anything cyber security related!"

        return "I am not sure about that. You can ask me about phishing, URL scanning, email analysis, clone detection, PDF reports, BERT, Machine Learning or how to use PhishShield AI!"

    reply = get_reply(message)
    return jsonify({'reply': reply})
from email_fetcher import fetch_emails

@app.route('/fetch/emails', methods=['POST'])
def fetch_inbox():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    data     = request.get_json()
    email    = data.get('email', '')
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'error': 'Email and password required'})

    result = fetch_emails(email, password, limit=10)

    if not result['success']:
        return jsonify({'success': False, 'error': result['error']})

    # NOTE: fetching no longer scans anything here. Scanning (rule-based
    # keyword matching + URL analysis on any links, via analyze_email /
    # analyze_email_with_attachments) only happens when the user explicitly
    # hits "Scan All Emails" -> /scan/email/bulk. This endpoint just returns
    # the raw fetched emails (subject/from/date/body/attachments) so the
    # list can be shown before any scan has run.
    emails_out = []
    for em in result['emails']:
        emails_out.append({
            'subject'     : em['subject'],
            'from'        : em['from'],
            'date'        : em['date'],
            'body'        : em['body'],
            'body_preview': em['body'][:100] + ('...' if len(em['body']) > 100 else ''),
            # Raw attachment references (not yet scanned) - filepath/
            # original_filename/content_type/size_bytes, as saved to the
            # temp dir by email_fetcher.fetch_emails(). These get scanned
            # (and cleaned up) only when /scan/email/bulk or
            # /scan/email/individual actually runs on this email.
            'attachments' : em.get('attachments', [])
        })

    return jsonify({'success': True, 'emails': emails_out})

def _scan_email_with_attachments(subject, body, attachments, sender='', date=''):
    """
    Shared rule-based scan used by both /scan/email/bulk and
    /scan/email/individual: keyword/urgency matching on the email body
    (analyze_email_deep) PLUS URL-analyzer-based link checks PLUS static
    attachment analysis, combined into one worst-case verdict via
    analyze_email_with_attachments().

    `attachments` is the raw list of {'filepath', 'original_filename', ...}
    dicts as returned by /fetch/emails - these files are scanned once here
    and then deleted, since they're temp copies. If an attachment's file
    was already scanned (and cleaned up) by an earlier scan of the same
    email, it's skipped here rather than erroring out.
    """
    attachments = attachments or []
    existing_attachments = [
        a for a in attachments
        if a.get('filepath') and os.path.exists(a['filepath'])
    ]
    already_scanned_count = len(attachments) - len(existing_attachments)

    result = analyze_email_with_attachments(
        subject, body,
        existing_attachments if existing_attachments else None,
        sender=sender, date=date
    )

    if already_scanned_count:
        result['attachments_unavailable'] = already_scanned_count

    # Clean up the temp attachment files now that they've been scanned once
    for att in existing_attachments:
        try:
            os.remove(att['filepath'])
        except OSError:
            pass

    return result


@app.route('/scan/email/bulk', methods=['POST'])
def bulk_scan():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    data    = request.get_json()
    emails  = data.get('emails', [])
    results = []

    for em in emails:
        # Rule-based analysis: phishing keyword/urgency matching on the
        # body (email_analyzer.py) + URL-analyzer link checks
        # (url_analyzer.evaluate_link_risk) + attachment static analysis -
        # this is what actually decides HIGH vs LOW here, run fresh on the
        # full fetched body every time "Scan All Emails" is clicked.
        result = _scan_email_with_attachments(
            em.get('subject', ''),
            em.get('body', ''),
            em.get('attachments', []),
            sender=em.get('from', ''),
            date=em.get('date', '')
        )
        results.append({
            'subject'      : em.get('subject', 'No Subject'),
            'from'         : em.get('from', 'Unknown'),
            'date'         : em.get('date', ''),
            'threat_level' : result['threat_level'],
            'confidence'   : result['confidence'],
            'urgency_score': result['urgency_score'],
            'total_score'  : result['total_score'],
            'attachments'  : [
                {
                    'filename'    : a['filename'],
                    'threat_level': a['threat_level'],
                    'confidence'  : a['confidence'],
                    'reasons'     : a['reasons']
                } for a in result.get('attachments', [])
            ]
        })
        save_scan(
            session['user'], 'Email',
            em.get('subject',''),
            result['threat_level'],
            result['confidence']
        )

    results.sort(
        key=lambda x: (
            0 if x['threat_level']=='HIGH' else
            1 if x['threat_level']=='MEDIUM' else 2
        )
    )

    return jsonify({'success': True, 'results': results})


@app.route('/scan/email/individual', methods=['POST'])
def individual_scan():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    data       = request.get_json()
    subject    = data.get('subject', '')
    body       = data.get('body', '')
    sender     = data.get('from', '')
    date       = data.get('date', '')
    # Raw attachment file references from the fetched email (not yet
    # scanned) - scanned fresh here, same as bulk scan. Accept the older
    # 'attachment_results' key too in case any cached frontend still sends it.
    attachments = data.get('attachments', data.get('attachment_results', []))

    result = _scan_email_with_attachments(subject, body, attachments, sender=sender, date=date)

    save_scan(
        session['user'], 'Email',
        subject, result['threat_level'],
        result['confidence']
    )

    return jsonify(result)

if __name__ == '__main__':
    init_db()
    print("✅ Database ready!")
    print("✅ ML Model loaded!")
    print("🚀 PhishShield AI running at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)