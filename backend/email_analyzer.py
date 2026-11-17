import re
from url_analyzer import evaluate_link_risk, BRAND_DOMAINS


_NON_CLICKABLE_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.bmp', '.ico',
    '.css', '.woff', '.woff2', '.ttf',
)


def _is_non_clickable_resource(url):
    """
    True for embedded resource links (images, tracking pixels, stylesheet
    assets, fonts) that appear in email HTML but are never something the
    recipient clicks - they're just rendered/loaded automatically. These
    should never be judged as phishing links: a tracking-pixel or logo
    image hosted on a CDN domain isn't a threat the way a clickable
    "verify your account" link is, and scoring them the same way was
    causing ordinary marketing/newsletter emails (full of header/footer
    images) to come back HIGH risk for no real reason.
    """
    path = url.split('?')[0].split('#')[0].lower()
    return path.endswith(_NON_CLICKABLE_EXTENSIONS)


def _dedupe_overlapping_matches(matched_words):
    """If one matched phrase is a substring of another matched phrase
    (e.g. 'immediate' matching inside 'immediately'), that's the SAME
    textual occurrence being counted twice, artificially inflating the
    score for what's really just one phrase. Keep only the longer/more
    specific match in that case."""
    return [
        w for w in matched_words
        if not any(w != other and w in other for other in matched_words)
    ]


def check_sender_mismatch(full_text, sender):
    """
    Real signal: does the email CLAIM to be from a known brand (that
    brand's name appears in the subject/body) while the actual sender
    address is NOT on that brand's real domain? That's classic
    impersonation - e.g. "Your PayPal account has unusual activity"
    sent from some unrelated address.

    This replaces a broken earlier version that scanned for ANY email
    address mentioned anywhere in the text (footer, unsubscribe links,
    etc.) against a 6-domain whitelist (gmail/yahoo/outlook/hotmail/
    paypal/amazon) - that flagged nearly every legitimate business email
    (support@company.com, no-reply@company.com, and so on) even though
    nothing was actually wrong, because it never even looked at the real
    sender in the first place.

    Returns (mismatch_count, [brand names that mismatched]).
    """
    if not sender:
        return 0, []

    match = re.search(r'[\w.-]+@([\w.-]+)', sender)
    sender_domain = match.group(1).lower() if match else ''
    if not sender_domain:
        return 0, []

    # Strip out URLs before searching for brand mentions. Emails routinely
    # embed third-party resource links (Google Fonts, CDN-hosted images,
    # analytics/tracking beacons) whose DOMAIN happens to contain a brand
    # word (e.g. "fonts.googleapis.com" contains "google") even though the
    # email never actually claims to be from that brand anywhere in its
    # visible text. Only a genuine mention in the readable text should
    # count as an impersonation claim.
    text_without_urls = re.sub(r'http[s]?://\S+', ' ', full_text)

    mismatched = []
    for brand, real_domain in BRAND_DOMAINS.items():
        if re.search(r'\b' + re.escape(brand) + r'\b', text_without_urls) and real_domain not in sender_domain:
            mismatched.append(brand)

    return len(mismatched), mismatched


def analyze_email(subject, body, sender=''):
    full_text = f"{subject} {body}".lower()
    urgency_words = [

    # Direct urgency
    'urgent', 'urgently', 'immediate', 'immediately',
    'right now', 'right away', 'as soon as possible',
    'asap', 'without delay', 'no delay', 'instantly',
    'at once', 'straightaway', 'promptly',

    # Time pressure
    'limited time', 'time sensitive', 'time is running out',
    'running out of time', 'expires today', 'expiring soon',
    'expiration', 'deadline', 'last chance', 'final notice',
    'final warning', 'last reminder', 'last opportunity',
    'within 24 hours', 'within 48 hours', 'within 12 hours',
    'by end of day', 'before midnight', 'today only',
    'this week only', '24 hours left', '48 hours left',
    'hours remaining', 'days remaining', 'act before',

    # Account threats
    'suspended', 'account suspended', 'your account has been',
    'account will be closed', 'account will be terminated',
    'account will be deactivated', 'account locked',
    'account on hold', 'access denied', 'access blocked',
    'account disabled', 'account frozen', 'temporarily locked',
    'permanently closed', 'permanently deleted',
    'account compromised', 'account hacked',
    'unauthorized access', 'unusual activity detected',
    'suspicious activity', 'suspicious login',
    'unrecognized login', 'new login detected',
    'security breach', 'data breach',

    # Action demands
    'verify now', 'verify immediately', 'verify your account',
    'verify your identity', 'confirm now', 'confirm immediately',
    'confirm your account', 'confirm your email',
    'click here', 'click here now', 'click the link',
    'click below', 'click the button', 'tap here',
    'follow this link', 'open the link', 'visit link',
    'update now', 'update immediately', 'update your account',
    'update your information', 'update your details',
    'update your payment', 'update billing',
    'validate now', 'validate your account',
    'authenticate now', 'authenticate yourself',
    'log in now', 'sign in now', 'login immediately',
    'reactivate now', 'restore access', 'restore now',

    # Consequence threats
    'or else', 'otherwise', 'failure to respond',
    'failure to comply', 'if you do not', 'if you fail',
    'if we do not hear', 'permanent suspension',
    'permanent termination', 'permanent deletion',
    'lose access', 'lose your account', 'lose your data',
    'legal action', 'legal proceedings', 'law enforcement',
    'report to authorities', 'criminal charges',
    'forwarded to police',

    # Security alerts
    'security alert', 'security warning', 'security notice',
    'security update required', 'security check required',
    'password expired', 'password must be changed',
    'reset your password', 'change your password',
    'two factor required', 'verification required',
    'identity verification', 'kyc required',
    'document required', 'submit documents',

    # Money and rewards
    'you have won', 'you are selected', 'congratulations',
    'you are a winner', 'claim your prize', 'claim now',
    'claim your reward', 'free gift', 'free offer',
    'special offer', 'exclusive offer', 'limited offer',
    'unclaimed funds', 'pending transfer', 'funds on hold',
    'payment pending', 'payment failed', 'payment declined',
    'refund pending', 'refund available', 'tax refund',
    'lottery winner', 'jackpot winner',

    # Trust manipulation
    'dear customer', 'dear user', 'dear valued customer',
    'dear account holder', 'dear member', 'dear client',
    'this is not spam', 'this is official',
    'from our security team', 'from our support team',
    'from customer service', 'official notice',
    'important notice', 'important update',
    'important information', 'action required',
    'response required', 'reply required',
    'do not ignore', 'do not delete',
    'read immediately', 'open immediately',

    # OTP and verification
    'otp', 'one time password', 'verification code',
    'enter the code', 'code expires', 'code valid for',
    'do not share', 'never share your otp',

    # Invoice and billing
    'invoice attached', 'invoice due', 'payment due',
    'overdue payment', 'outstanding balance', 'amount due',
    'billing issue', 'billing error', 'credit card declined',
    'subscription expired', 'subscription cancelled',
    'renewal required', 'renew now', 'renew immediately',
]
    urgency_found = _dedupe_overlapping_matches([w for w in urgency_words if w in full_text])
    urgency_score = len(urgency_found)

    links = re.findall(r'http[s]?://\S+', body)
    links = [l.rstrip('"\'<>)') for l in links]
    links = [l for l in links if not _is_non_clickable_resource(l)]
    # Judge each link with the SAME rules as the standalone URL scanner
    # (https required, valid/trusted TLD, not a typosquat, not high-entropy,
    # etc) instead of the old plain-keyword substring match. Any link that
    # fails those checks is treated as a phishing link.
    link_risk_results = [evaluate_link_risk(l) for l in links]
    suspicious_links   = [r['url'] for r in link_risk_results if r['is_risky']]
    phishing_link_reasons = {
        r['url']: r['reasons'] for r in link_risk_results if r['is_risky']
    }
    has_phishing_link = len(suspicious_links) > 0

    impersonal = 1 if any(
        g in full_text for g in [
            'dear customer', 'dear user',
            'dear account holder', 'valued customer'
        ]
    ) else 0

    threat_words = [
    'your account will be',
    'will be suspended',
    'will be closed',
    'will be terminated',
    'legal action',
    'law enforcement',
    'account has been hacked',
    'account has been compromised',
    'unauthorized access detected',
    'security breach detected',
    'criminal charges will be filed',
    'report to police',
    'your personal data',
    'your information has been stolen',
    'identity theft',
    'fraud detected',
    'fraudulent activity',
]
    threat_found  = _dedupe_overlapping_matches([w for w in threat_words if w in full_text])
    threat_score  = len(threat_found) 
    money_words = [
    'free', 'winner', 'prize', 'cash',
    'reward', 'offer', 'discount', 'earn money',
    'make money', 'investment', 'lottery',
    'jackpot', 'bonus', 'gift card',
    'amazon gift', 'free iphone',
    'unclaimed money', 'inheritance',
    'million dollars', 'bank transfer',
    'wire transfer', 'western union',
    'bitcoin', 'crypto', 'cryptocurrency',
    'tax refund', 'government refund',
    'covid relief', 'stimulus check',
    'charity donation', 'help needed',
]
    money_found = _dedupe_overlapping_matches([w for w in money_words if w in full_text])
    money_score = len(money_found)

    mismatch, mismatch_brands = check_sender_mismatch(full_text, sender)

    total = (
        urgency_score * 2 +
        threat_score  * 3 +
        money_score       +
        len(suspicious_links) * 2 +
        impersonal            +
        mismatch
    )

    if total >= 8:
        threat_level = "HIGH"
        confidence   = min(95, 70 + total * 2)
    elif total >= 4:
        threat_level = "MEDIUM"
        confidence   = min(75, 50 + total * 3)
    else:
        threat_level = "LOW"
        confidence   = max(20, 30 - total * 5)

    # A confirmed phishing-style link (fails the same https / trusted-TLD /
    # typosquat / entropy checks the URL scanner uses) is a decisive signal
    # on its own. Regardless of how mild the rest of the email's wording
    # scores, an email containing a link like this should never come back
    # as LOW or MEDIUM risk.
    if has_phishing_link:
        threat_level = "HIGH"
        confidence   = max(confidence, 90)

    return {
        "threat_level"     : threat_level,
        "confidence"       : round(confidence, 2),
        "urgency_score"    : urgency_score,
        "urgency_found"    : urgency_found,
        "threat_score"     : threat_score,
        "threat_found"     : threat_found,
        "money_score"      : money_score,
        "money_found"      : money_found,
        "suspicious_links" : suspicious_links,
        "has_phishing_link": has_phishing_link,
        "phishing_link_reasons": phishing_link_reasons,
        "impersonal"       : bool(impersonal),
        "sender_mismatch"  : mismatch,
        "sender_mismatch_brands": mismatch_brands,
        "total_score"      : total
    }


def analyze_email_deep(subject, body, sender='', date=''):
    basic = analyze_email(subject, body, sender=sender)
    full_text = f"{subject} {body}".lower()

    # Extra deep checks
    all_links = re.findall(r'http[s]?://\S+', body)

    # Check for HTML in body
    has_html = 1 if re.search(r'<[^>]+>', body) else 0

    # Check for attachments mentioned
    attachment_words = ['attachment', 'attached', 'document', 'invoice', 'receipt', '.pdf', '.zip', '.exe']
    has_attachment_mention = sum(1 for w in attachment_words if w in full_text)

    # Spelling mistakes (simple check)
    common_misspells = ['recieve','occurence','seperate','definately','untill']
    spelling_errors = sum(1 for w in common_misspells if w in full_text)

    # All suspicious words found
    all_suspicious = (
        basic['urgency_found'] +
        basic['threat_found']  +
        basic['money_found']
    )

    # Risk breakdown
    breakdown = []
    if basic['urgency_score'] > 0:
        breakdown.append({
            'category' : 'Urgency Words',
            'count'    : basic['urgency_score'],
            'words'    : basic['urgency_found'],
            'risk'     : 'HIGH' if basic['urgency_score'] > 2 else 'MEDIUM'
        })
    if basic['threat_score'] > 0:
        breakdown.append({
            'category' : 'Threat Language',
            'count'    : basic['threat_score'],
            'words'    : basic['threat_found'],
            'risk'     : 'HIGH'
        })
    if basic['money_score'] > 0:
        breakdown.append({
            'category' : 'Money/Reward Words',
            'count'    : basic['money_score'],
            'words'    : basic['money_found'],
            'risk'     : 'MEDIUM'
        })
    if basic['suspicious_links']:
        # Flatten each link's specific reasons (from evaluate_link_risk)
        # into the breakdown so the UI can show *why* each link failed,
        # not just that it did.
        link_words = []
        for link in basic['suspicious_links']:
            reasons_for_link = basic['phishing_link_reasons'].get(link, [])
            if reasons_for_link:
                link_words.append(link + ' — ' + '; '.join(reasons_for_link))
            else:
                link_words.append(link)
        breakdown.append({
            'category' : 'Phishing Link Detected',
            'count'    : len(basic['suspicious_links']),
            'words'    : link_words,
            'risk'     : 'HIGH'
        })
    if basic['impersonal']:
        breakdown.append({
            'category' : 'Impersonal Greeting',
            'count'    : 1,
            'words'    : ['dear customer/user detected'],
            'risk'     : 'MEDIUM'
        })
    if basic['sender_mismatch'] > 0:
        breakdown.append({
            'category' : 'Sender Domain Mismatch',
            'count'    : basic['sender_mismatch'],
            'words'    : [
                f"claims to be '{b}' but sender is not on {b}'s real domain"
                for b in basic.get('sender_mismatch_brands', [])
            ],
            'risk'     : 'HIGH'
        })
    if has_attachment_mention:
        breakdown.append({
            'category' : 'Attachment Mention',
            'count'    : has_attachment_mention,
            'words'    : ['attachment/document mentioned'],
            'risk'     : 'MEDIUM'
        })

    return {
        **basic,
        'sender'                  : sender,
        'date'                    : date,
        'subject'                 : subject,
        'all_links'               : all_links,
        'has_html'                : bool(has_html),
        'attachment_mention'      : has_attachment_mention,
        'spelling_errors'         : spelling_errors,
        'all_suspicious_words'    : all_suspicious,
        'breakdown'               : breakdown,
        'recommendation'          : get_recommendation(basic['threat_level'])
    }


def get_recommendation(threat_level):
    if threat_level == 'HIGH':
        return [
            'Do NOT click any links in this email',
            'Do NOT download any attachments',
            'Report this email as phishing immediately',
            'Block the sender email address',
            'Inform your IT security team'
        ]
    elif threat_level == 'MEDIUM':
        return [
            'Be cautious with this email',
            'Verify the sender before clicking any links',
            'Do not provide personal information',
            'Check the sender email address carefully'
        ]
    else:
        return [
            'This email appears safe',
            'Always stay cautious with unknown senders',
            'Never share passwords via email'
        ]


from attachment_analyzer import analyze_attachment


def analyze_email_with_attachments(subject, body, attachment_paths=None, sender='', date=''):
    """
    Combines the deep email body/subject analysis with static attachment
    analysis. `attachment_paths` is a list of dicts:
        [{'filepath': '/tmp/xyz.pdf', 'original_filename': 'invoice.pdf'}, ...]
    Returns the same shape as analyze_email_deep()'s result plus an
    'attachments' key listing per-file results. The overall threat_level
    and confidence are escalated to the worst of (email body result, any
    attachment result), so a polite-sounding email with a malicious
    attachment still gets flagged correctly.
    """
    email_result = analyze_email_deep(subject, body, sender=sender, date=date)

    attachment_results = []
    if attachment_paths:
        for att in attachment_paths:
            result = analyze_attachment(
                att['filepath'],
                original_filename=att.get('original_filename')
            )
            attachment_results.append(result)

    level_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    worst_level = email_result['threat_level']
    worst_confidence = email_result['confidence']

    for att_result in attachment_results:
        if level_rank[att_result['threat_level']] > level_rank[worst_level]:
            worst_level = att_result['threat_level']
            worst_confidence = att_result['confidence']
        elif level_rank[att_result['threat_level']] == level_rank[worst_level]:
            worst_confidence = max(worst_confidence, att_result['confidence'])

    combined = dict(email_result)
    combined['threat_level'] = worst_level
    combined['confidence'] = worst_confidence
    combined['attachments'] = attachment_results
    combined['email_only_threat_level'] = email_result['threat_level']
    combined['email_only_confidence'] = email_result['confidence']
    if worst_level != email_result['threat_level']:
        combined['recommendation'] = get_recommendation(worst_level)
    return combined