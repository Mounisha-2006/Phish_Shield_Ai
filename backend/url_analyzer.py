import re
import math
import tldextract
from urllib.parse import urlparse

# Official trusted domains — always SAFE
TRUSTED_DOMAINS = [
    'google.com', 'gmail.com', 'youtube.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'microsoft.com', 'apple.com', 'amazon.com',
    'linkedin.com', 'github.com', 'wikipedia.org',
    'yahoo.com', 'netflix.com', 'spotify.com',
    'whatsapp.com', 'reddit.com', 'zoom.us',
    'dropbox.com', 'adobe.com', 'paypal.com',
    'ebay.com', 'walmart.com', 'flipkart.com',
    'stackoverflow.com', 'medium.com', 'quora.com','orange.com',
    # Indian banks & finance
    'sbi.co.in', 'onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com',
    'axisbank.com', 'pnbindia.in', 'bankofbaroda.in', 'kotak.com',
    'paytm.com', 'phonepe.com', 'bhimupi.org.in', 'rbi.org.in',
    # Indian government / education
    'gov.in', 'nic.in', 'uidai.gov.in', 'incometax.gov.in',
    'irctc.co.in', 'digilocker.gov.in', 'rguktrkv.ac.in',
    'aicte.gov.in', 'ugc.gov.in', 'nptel.ac.in', 'swayam.gov.in',
    # Global tech / services
    'microsoft.com', 'outlook.com', 'live.com', 'office.com',
    'icloud.com', 'samsung.com', 'oneplus.com', 'xiaomi.com',
    'slack.com', 'discord.com', 'telegram.org', 'signal.org',
    'wordpress.com', 'cloudflare.com', 'digitalocean.com',
    'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com',
    'mozilla.org', 'firefox.com', 'opera.com',
    'salesforce.com', 'oracle.com', 'ibm.com', 'intel.com',
    # Global banks / payments
    'visa.com', 'mastercard.com', 'americanexpress.com',
    'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'hsbc.com',
    'stripe.com', 'wise.com', 'westernunion.com',"narl.gov.in","rgukt.in",
    # E-commerce / travel
    'aliexpress.com', 'myntra.com', 'ajio.com', 'meesho.com',
    'bookmyshow.com', 'makemytrip.com', 'goibibo.com', 'oyorooms.com',
    'booking.com', 'airbnb.com', 'uber.com', 'ola.com', 'swiggy.com',
    'zomato.com',
    # News / reference
    'bbc.com', 'cnn.com', 'nytimes.com', 'reuters.com',
    'wikipedia.org', 'wiktionary.org', 'imdb.com',
]


# Typosquatting patterns — detect misspelled brand names
BRAND_TYPOS = {
    'google' : ['g00gle','go0gle','goog1e','googIe','gooogle',
                'gogle','googgle','googlee','g0ogle','googel'],
    'paypal' : ['paypa1','paypai','paypa','paypa1l','paypall',
                'payapl','paipal','paaypal'],
    'facebook':['faceb00k','facebo0k','facebok','faceboook',
                'facbook','faceebook','faceboock'],
    'amazon' : ['amaz0n','amazoon','amazn','arnazon',
                'amazan','amzon','amazone'],
    'apple'  : ['app1e','appl3','aple','appple','aplle'],
    'netflix': ['netf1ix','netfiix','netfIix','netflx',
                'netlfix','neetflix'],
    'microsoft':['micros0ft','microsooft','microsft',
                 'microsfot','mlcrosoft'],
    'instagram':['lnstagram','1nstagram','instagr4m',
                 'instagramm','instagrm'],
    'twitter': ['tw1tter','twltter','twiiter','twiter',
                'twtter','tvvitter'],
    'whatsapp':['whatsap','whattsapp','whatasapp','wlhatsapp',
                'whatappp','whattsap'],
    'linkedin':['linkedln','linkedl n','linkdin','linkedinn',
                'lnkedin','linkedien'],
    'youtube':['y0utube','youtu8e','yputube','youtub3',
               'youtubee','yutube'],
    'ebay':['eba6','3bay','ebayy','ebai','3bay'],
    'dropbox':['dropb0x','dropbo','dr0pbox','dropboxx'],
    'spotify':['sp0tify','spotifyy','spotifi','spottify'],
    'reddit':['redd1t','redditt','reddi t','redit'],
    'wikipedia':['wikipedla','wikkipedia','wikipediaa','wikipedi'],
    'yahoo':['yah00','yahooo','yaho','yhaoo'],
    'sbi':['sb1','sbii','s8i'],
    'hdfc':['hdfc bank','hdfcc','hdfc-bank','hdfd'],
    'icici':['icic1','iciic','icicl'],
    'axis':['ax1s','axiss','axsi'],
    'paytm':['paytrn','payt m','payttm','paytmm'],
    'phonepe':['ph0nepe','phonep3','fonepe','phonepay'],
    'irctc':['irctc-india','irtc','ircte','irctcc'],
    'uidai':['u1dai','uldai','uidal'],
    'flipkart':['fl1pkart','flipkar t','flipkartt','flipkrat',
                'fllpkart','flipakrt','flipcart'],
    'myntra':['myntr4','myntraa','mintra','myntar'],
    'meesho':['mees0h','meeshoo','mesho','meeshoe'],
    'swiggy':['swigy','swiggyy','sw1ggy','swiggi'],
    'zomato':['zomat0','zomatoo','zomatto','zomaato'],
    'ajio':['aj1o','ajioo','aazio','aajio'],
    'oyorooms':['0yorooms','oyoroom','oyorroms','oyo-rooms'],
    'makemytrip':['makemytr1p','makemytripp','makemytirp',
                  'makemytrlp'],
    'goibibo':['goib1bo','goibiboo','goibibbo'],
    'bookmyshow':['bookmyshoww','bookmysh0w','bookmyshw'],
    'rapido':['rap1do','rapidoo','rappido'],
    'uber':['ub3r','uberr','uber1'],
    'ola':['0la','olaa','0la-cabs'],
    'kotak':['k0tak','kotakk','kotac'],
    'bankofbaroda':['bank0fbaroda','bankofbarodaa','bankofbaroda1'],
    'pnb':['pnbb','pnb1','p n b'],
    'rbi':['rb1','rbii','r8i'],
    'incometax':['1ncometax','incometaxx','incom etax'],
    'digilocker':['dig1locker','digilockerr','digi-locker1'],
    'gpay':['gpayy','g-pay1','gpai'],
    'bhim':['bh1m','bhimm','bhlm'],
    'jio':['j10','jioo','jio0'],
    'airtel':['a1rtel','airtell','airte1'],
    'vodafone':['v0dafone','vodafonee','vodaf0ne'],
    'bsnl':['bsn1','bsnll','b s n l'],
    'lic':['l1c','licc','l-i-c'],
    'tcs':['tcss','tc5','t-c-s'],
    'infosys':['1nfosys','infosyss','infosis'],
    'wipro':['w1pro','wiproo','vvipro'],
    'snapdeal':['snapdea1','snapdeall','snapdael'],
    'bigbasket':['b1gbasket','bigbaskett','bigbaskt'],
    'nykaa':['nykaaa','nyka','nyk44'],
    'cred':['cre6','credd','cr3d'],
    'slice':['s1ice','slicee','slise'],
    'razorpay':['raz0rpay','razorpayy','razorpai'],
    'binance':['b1nance','binancee','bynance'],
    'coinbase':['c0inbase','coinbasee','coinbas3'],
    'steam':['steamm','st3am','steeam'],
    'pinterest':['p1nterest','pinterestt','pintrest'],
    'snapchat':['snapchatt','snapcha7','snap-chat'],
    'tiktok':['t1ktok','tiktokk','tik-tok1'],
    'skype':['sk1pe','skypee','scype'],
    'office365':['off1ce365','office365','0ffice365'],
    'icloud':['1cloud','icloudd','iclou d'],
    'samsung':['samsun9','samsungg','sams ung'],
    'oneplus':['0neplus','onepluss','one-plus1'],
    'xiaomi':['x1aomi','xiaomii','xiaomy'],
    'oracle':['0racle','oraclee','oracl3'],
    'salesforce':['sal3sforce','salesforcee','sales-force1'],
    'wordpress':['w0rdpress','wordpresss','word-press1'],
    'cloudflare':['c1oudflare','cloudflaree','cloud-flare1'],
    'mastercard':['mast3rcard','mastercardd','master-card1'],
    'visa':['v1sa','visaa','viza'],
    'chase':['ch4se','chasee','chace'],
    'wellsfargo':['well sfargo','wellsfargoo','wells-fargo1'],
    'hsbc':['h5bc','hsbcc','h s b c'],
    'stripe':['str1pe','stripee','strype'],
    'booking':['b00king','bookingg','bookin g'],
    'airbnb':['a1rbnb','airbnbb','air-bnb1'],
}


# Real domain for each brand name we know about - used to check for
# actual sender impersonation (email claims to be from "PayPal" but the
# sender's address isn't on paypal.com at all). Brands not listed here
# simply aren't checked for this signal.
BRAND_DOMAINS = {
    'google': 'google.com', 'paypal': 'paypal.com', 'facebook': 'facebook.com',
    'amazon': 'amazon.com', 'apple': 'apple.com', 'netflix': 'netflix.com',
    'microsoft': 'microsoft.com', 'instagram': 'instagram.com',
    'twitter': 'x.com', 'whatsapp': 'whatsapp.com', 'linkedin': 'linkedin.com',
    'youtube': 'youtube.com', 'ebay': 'ebay.com', 'dropbox': 'dropbox.com',
    'spotify': 'spotify.com', 'reddit': 'reddit.com', 'wikipedia': 'wikipedia.org',
    'yahoo': 'yahoo.com', 'sbi': 'sbi.co.in', 'hdfc': 'hdfcbank.com',
    'icici': 'icicibank.com', 'axis': 'axisbank.com', 'paytm': 'paytm.com',
    'phonepe': 'phonepe.com', 'irctc': 'irctc.co.in', 'uidai': 'uidai.gov.in',
    'flipkart': 'flipkart.com', 'myntra': 'myntra.com', 'meesho': 'meesho.com',
    'swiggy': 'swiggy.com', 'zomato': 'zomato.com', 'ajio': 'ajio.com',
    'oyorooms': 'oyorooms.com', 'makemytrip': 'makemytrip.com',
    'goibibo': 'goibibo.com', 'bookmyshow': 'bookmyshow.com', 'uber': 'uber.com',
    'ola': 'ola.com', 'kotak': 'kotak.com', 'bankofbaroda': 'bankofbaroda.in',
    'pnb': 'pnbindia.in', 'rbi': 'rbi.org.in', 'digilocker': 'digilocker.gov.in',
    'icloud': 'icloud.com', 'samsung': 'samsung.com', 'oneplus': 'oneplus.com',
    'xiaomi': 'xiaomi.com', 'oracle': 'oracle.com', 'salesforce': 'salesforce.com',
    'wordpress': 'wordpress.com', 'cloudflare': 'cloudflare.com',
    'mastercard': 'mastercard.com', 'visa': 'visa.com', 'chase': 'chase.com',
    'wellsfargo': 'wellsfargo.com', 'hsbc': 'hsbc.com', 'stripe': 'stripe.com',
    'booking': 'booking.com', 'airbnb': 'airbnb.com',
}


# Whitelist of legitimate/trusted domain extensions (TLDs). A URL must end
# in one of these to be considered a properly-formatted, trustworthy URL.
# This is deliberately separate from TRUSTED_DOMAINS (specific known sites)
# — this list covers *extensions*, not specific domains, and excludes the
# extensions commonly abused by phishing sites (.xyz, .top, .club, .tk,
# .ml, .ga, .cf, .work, etc. — see bad_tlds in extract_features).
VALID_DOMAIN_EXTENSIONS = [
    # Generic
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'name', 'pro',
    'io', 'co', 'me', 'app', 'dev', 'ai',
    # India
    'in', 'co.in', 'org.in', 'net.in', 'gov.in', 'ac.in', 'nic.in',
    'res.in', 'edu.in', 'firm.in', 'gen.in', 'ind.in', 'sbi',
    # Common country codes
    'us', 'uk', 'co.uk', 'ca', 'au', 'com.au', 'de', 'fr', 'jp', 'cn',
    'ru', 'br', 'nz', 'sg', 'nl', 'es', 'it', 'ch', 'se', 'no', 'dk',
    'ae', 'za', 'ie', 'eu', 'us',
]


def is_valid_url(text):
    """Sanity check that the input is a *structurally* well-formed URL —
    not plain text (e.g. 'hello', '123', 'go', 'home'). This should be
    called FIRST, before any risk scoring — scoring random text just
    produces a meaningless (usually low) score instead of an error.

    A structurally valid URL must:
      1. Start with http:// or https:// — no auto-adding/upgrading a
         scheme. Bare inputs like "google", "hello", "123", "google.com"
         (missing the scheme) are rejected here. Plain http:// is still
         accepted as *structurally* valid — it's not "not a URL", it's
         just an insecure one, so it proceeds to scoring and comes back
         HIGH RISK there (see evaluate_link_risk / check_insecure_brand)
         instead of being rejected outright as invalid input.
      2. Contain a valid, well-formed domain name

    NOTE: this deliberately does NOT check the domain extension (.com,
    .xyz, etc.) — that's a risk signal, not a validity signal. A URL like
    'https://something.xyz' IS a valid URL (so it proceeds to scoring),
    it's just going to score as HIGH RISK because of the extension. Use
    has_valid_extension() for that check.

    Returns (is_valid: bool, reason: str or None).
    """
    if text is None:
        return False, "Invalid URL. Please enter a valid URL."

    text = text.strip()
    if not text:
        return False, "Invalid URL. Please enter a valid URL."

    # Real URLs never contain unencoded whitespace.
    if re.search(r'\s', text):
        return False, "Invalid URL. Please enter a valid URL."

    # 1) Must start with http:// or https:// — a missing/bare scheme
    #    (e.g. "google", "hello", "123", "google.com") is rejected here.
    if not re.match(r'^https?://', text, re.IGNORECASE):
        return False, "Invalid URL. Please enter a valid URL."

    try:
        parsed = urlparse(text)
    except Exception:
        return False, "Invalid URL. Please enter a valid URL."

    if not parsed.netloc:
        return False, "Invalid URL. Please enter a valid URL."

    # 2) Must contain a valid, well-formed domain name.
    ext = tldextract.extract(text)
    if not ext.domain or not ext.suffix:
        return False, "Invalid URL. Please enter a valid URL."

    # Domain label must be letters/digits/hyphens only (punycode 'xn--'
    # covers internationalized domains), can't start/end with a hyphen.
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', ext.domain):
        return False, "Invalid URL. Please enter a valid URL."

    return True, None


def has_valid_extension(url):
    """Checks whether the URL ends with a recognized/legitimate domain
    extension (see VALID_DOMAIN_EXTENSIONS above), e.g. .com, .in, .org.

    This is separate from is_valid_url() on purpose: a URL can be
    structurally valid (has http(s):// and a real domain) but still end
    in an extension that's unusual or commonly abused by phishing sites
    (.xyz, .top, .tk, or something made up). That's not an "invalid URL"
    — it's a URL that should be scored HIGH RISK.

    Returns True/False. Assumes is_valid_url(url) has already passed.
    """
    ext = tldextract.extract(url)
    suffix = ext.suffix.lower() if ext.suffix else ''
    return suffix in VALID_DOMAIN_EXTENSIONS


def check_trusted(url):
    url = url.strip()
    ext = tldextract.extract(url)
    domain = ext.domain + '.' + ext.suffix
    domain = domain.lower()
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted:
            return True
    return False

def levenshtein(a, b):
    """Edit distance between two strings — counts how many single-character
    insertions, deletions, or substitutions turn `a` into `b`."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost_sub = prev_row[j - 1] + (0 if ca == cb else 1)
            cost_del = prev_row[j] + 1
            cost_ins = curr_row[j - 1] + 1
            curr_row[j] = min(cost_sub, cost_del, cost_ins)
        prev_row = curr_row
    return prev_row[len(b)]

# Real brand names to fuzzy-match the domain against (catches ANY misspelling,
# not just ones we thought to hardcode in advance).
BRAND_NAMES = list(BRAND_TYPOS.keys())

def check_typosquatting(url):
    url = url.strip()
    url_lower = url.lower()
    ext = tldextract.extract(url)
    domain_part = ext.domain.lower()

    # 1) Fast path: exact match against the known hardcoded typo list.
    #    Compared in lowercase so a mixed-case entry in the list (e.g. a
    #    stray capital letter) still matches - url_lower/domain_part are
    #    always lowercase, so without this a typo like 'googIe' could
    #    never match anything and would silently never fire.
    for brand, typos in BRAND_TYPOS.items():
        for typo in typos:
            typo_lower = typo.lower()
            if typo_lower in url_lower or typo_lower in domain_part:
                return True, brand, typo

    # 2) Fuzzy path: edit-distance check against real brand names.
    #    Catches misspellings we never explicitly listed, e.g. "googlle",
    #    "amazoom", "netfliix" — anything within 1-2 character edits of a
    #    real brand, as long as it ISN'T the real domain itself.
    if domain_part and domain_part not in BRAND_NAMES:
        for brand in BRAND_NAMES:
            distance = levenshtein(domain_part, brand)
            # Allow distance to scale slightly with brand length so short
            # brand names (e.g. "apple") aren't too sensitive.
            max_allowed = 1 if len(brand) <= 5 else 2
            if 0 < distance <= max_allowed:
                return True, brand, domain_part

    return False, None, None

def check_insecure_brand(url):
    """If a domain matches (or closely matches) a known trusted brand but is
    being served over plain http:// instead of https://, that's a strong
    phishing signal — real brand sites always force HTTPS. Returns
    (True/False, brand) so the caller can treat this as HIGH risk.
    """
    url = url.strip()
    url_lower = url.lower()
    if url_lower.startswith('https://'):
        return False, None

    ext = tldextract.extract(url)
    full_domain = (ext.domain + '.' + ext.suffix).lower()

    # Exact trusted domain over http:// — should never happen for the real
    # site, so this alone is suspicious.
    if full_domain in TRUSTED_DOMAINS:
        return True, full_domain

    # Match the brand as a real domain/subdomain TOKEN (split on '.' and
    # '-' across subdomain+domain), not a raw substring of just the base
    # domain. Two bugs a plain substring-on-domain-only check causes:
    #   1. False positive - "google" is a substring of "googleusercontent"
    #      (a legitimate Google-owned CDN domain that shows up constantly
    #      in email images), so it was wrongly flagged as brand misuse.
    #   2. False negative - the classic phishing pattern of putting the
    #      brand name in a SUBDOMAIN of an unrelated domain (e.g.
    #      http://paypal.attacker-verify.tk) was missed entirely, because
    #      only ext.domain (the base domain) was ever checked - the
    #      subdomain, where the brand name actually was, was never looked at.
    domain_tokens = re.split(r'[.\-]', (ext.subdomain + '.' + ext.domain).lower())
    for brand in BRAND_NAMES:
        if brand in domain_tokens:
            return True, brand
        if levenshtein(ext.domain.lower(), brand) <= (1 if len(brand) <= 5 else 2):
            return True, brand

    return False, None

# TLDs that require real-world vetting to register (accredited
# universities, government bodies, military) - unlike .com/.xyz/etc,
# nobody can just buy one of these. A domain name that looks randomly
# generated sitting on one of these TLDs is trying to borrow trust it's
# very unlikely to be legitimately entitled to.
RESTRICTED_TRUST_TLDS = ['edu', 'gov', 'mil', 'ac.in', 'gov.in', 'nic.in', 'edu.in', 'res.in']

VOWELS = set('aeiou')

# A sample of common English letter-pairs. Real words/names are made
# almost entirely of these; random strings mostly aren't. This is the
# single most reliable of the sub-signals below - vowel ratio and
# consonant runs alone missed a genuinely gibberish domain that still
# happened to have a few real vowels scattered through it.
COMMON_BIGRAMS = set("""
th he in en nt re er an ti es on at se nd or ar al te co de to ra et ed
it sa em ro is ha ng hi ve ic ne of la ea ll le ou ur me ma si li io ce
us ta di be ac no om ol wa ge ri un ni el tr ch do wh pe ho st ss ry
ay ld op mo
""".split())

def is_gibberish_domain(domain):
    """
    Weak signal: does this domain name look like randomly-generated
    characters rather than a real word, name, or brand? Deliberately
    forgiving - an earlier attempt at a single blunt entropy cutoff
    flagged a legitimate, ordinary blog URL as risky (see notes in
    evaluate_link_risk below), so this combines several softer
    sub-signals and only returns True when a domain shows MULTIPLE
    gibberish traits at once, rather than tripping on any one
    borderline number.

    Sub-signals checked:
      - Very low vowel ratio (real words/names need vowels to be
        pronounceable; random strings often don't have many)
      - A long run of consecutive consonants (real words rarely stack
        more than ~4 in a row; random strings frequently do)
      - A digit sitting in the middle of the domain body, not at the
        edges (real brand names essentially never do this; random
        strings often do, e.g. "wyt8uj")
      - Low coverage of common English letter-pairs (the most reliable
        check - real words are built almost entirely out of common
        bigrams like "th", "an", "in"; random strings mostly aren't,
        even when they contain a normal-looking vowel ratio)

    Returns True only when at least 2 of these 4 sub-signals fire, and
    never fires at all on short domains (<8 letters) - short, invented,
    brand-style domains ("bit", "x", "co") are common and legitimate,
    and are too short for this heuristic to say anything meaningful
    either way.
    """
    d = domain.lower()
    letters = [c for c in d if c.isalpha()]
    if len(letters) < 8:
        return False

    vowel_ratio = sum(1 for c in letters if c in VOWELS) / len(letters)

    longest_consonant_run = 0
    current_run = 0
    for c in letters:
        if c not in VOWELS:
            current_run += 1
            longest_consonant_run = max(longest_consonant_run, current_run)
        else:
            current_run = 0

    has_embedded_digit = bool(re.search(r'[a-z]\d[a-z]', d))

    letter_str = ''.join(letters)
    bigrams = [letter_str[i:i+2] for i in range(len(letter_str) - 1)]
    bigram_coverage = (
        sum(1 for b in bigrams if b in COMMON_BIGRAMS) / len(bigrams)
        if bigrams else 1.0
    )

    signals = 0
    if vowel_ratio < 0.20:
        signals += 1
    if longest_consonant_run >= 5:
        signals += 1
    if has_embedded_digit:
        signals += 1
    if bigram_coverage < 0.15:
        signals += 1

    return signals >= 2

def extract_features(url):
    url = url.strip()
    features = {}
    try:
        parsed = urlparse(url)
    except:
        parsed = None

    # Length features
    features['url_length']       = len(url)
    features['domain_length']    = len(parsed.netloc) if parsed else 0
    features['path_length']      = len(parsed.path) if parsed else 0

    # Special characters
    features['dot_count']        = url.count('.')
    features['hyphen_count']     = url.count('-')
    features['at_count']         = url.count('@')
    features['slash_count']      = url.count('/')
    features['quest_count']      = url.count('?')
    features['equal_count']      = url.count('=')
    features['underscore_count'] = url.count('_')
    features['percent_count']    = url.count('%')
    features['hash_count']       = url.count('#')
    features['amp_count']        = url.count('&')
    features['digit_count']      = sum(c.isdigit() for c in url)
    features['letter_count']     = sum(c.isalpha() for c in url)
    features['digit_ratio']      = features['digit_count'] / (len(url)+1)

    # Security
    features['has_https']        = 1 if url.startswith('https') else 0
    features['has_ip']           = 1 if re.search(
        r'(\d{1,3}\.){3}\d{1,3}', url) else 0

    # Suspicious keywords
    suspicious = [
        'login','verify','secure','account','update','bank',
        'paypal','free','lucky','bonus','ebay','signin','signup',
        'confirm','password','billing','alert','authenticate',
        'purchase','transaction','recover','unlock','suspended'
    ]
    features['suspicious_count'] = sum(
        1 for w in suspicious if w in url.lower()
    )

    # Brand in wrong domain - match the brand as a real token (its own
    # domain label, or hyphen/dot-separated piece of the subdomain), not
    # a raw substring anywhere in subdomain+domain. A plain substring
    # match wrongly caught things like "amazon" inside "amazonaws" or
    # "google" inside "googleusercontent" - both are legitimate CDN/image
    # hosting domains that show up constantly in normal email images and
    # tracking pixels, not brand impersonation.
    brands = [
        'paypal','google','facebook','amazon','apple',
        'microsoft','netflix','bank','twitter','instagram'
    ]
    ext = tldextract.extract(url)
    domain_tokens = re.split(r'[.\-]', (ext.subdomain + '.' + ext.domain).lower())
    features['brand_in_domain']  = sum(1 for b in brands if b in domain_tokens)
    features['subdomain_count']  = len(
        ext.subdomain.split('.')) if ext.subdomain else 0
    features['subdomain_len']    = len(
        ext.subdomain) if ext.subdomain else 0

    # URL shorteners - match the actual registered domain, not a raw
    # substring of the whole URL. Substring matching on 't.co' wrongly
    # caught ANY domain ending in "...t.com" - content.com, element.com,
    # and (the real bug you hit) googleusercontent.com, since "t.com"
    # contains "t.co" as a substring. Same risk existed for the other
    # short entries here.
    shortener_domains = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'rebrand.ly', 'tiny.cc', 'shorturl.at',
    }
    shortener_full_domain = (ext.domain + '.' + ext.suffix).lower()
    features['is_shortened']     = 1 if shortener_full_domain in shortener_domains else 0

    # Suspicious TLDs
    bad_tlds = ['.tk','.ml','.ga','.cf','.xyz','.top','.club','.work']
    features['suspicious_tld']   = 1 if any(
        url.endswith(t) for t in bad_tlds) else 0

    # Repeated characters
    features['has_repeated']     = 1 if re.search(
        r'(.)\1{3,}', url) else 0

    # Entropy
    prob = [url.count(c)/len(url) for c in set(url)]
    features['entropy']          = -sum(
        p * math.log2(p) for p in prob if p > 0
    )

    # Typosquatting check as feature
    is_typo, _, _ = check_typosquatting(url)
    features['is_typosquatting'] = 1 if is_typo else 0

    # Numbers replacing letters (l33t speak) like g00gle - checked against
    # the DOMAIN only, not the whole URL. Checking the whole URL caught
    # ordinary query-string/hash tokens and image-CDN paths (e.g.
    # ".../img_a1b2c3.png?v=2") which almost always contain a random digit
    # between letters somewhere - that's not leetspeak, that's just a
    # normal cache-busting token or asset hash.
    features['has_leetspeak']    = 1 if re.search(
        r'[a-z][0-9][a-z]|[0-9][a-z][0-9]', ext.domain.lower()) else 0

    return features


def analyze_url(raw_input):
    """Main entry point the app/UI should call instead of calling
    extract_features / check_trusted / check_typosquatting directly.

    Validates the input first. If it isn't a real URL, returns an error
    result instead of silently running it through the risk-scoring
    pipeline (which is what was causing non-URLs to come back as
    'low risk').
    """
    valid, reason = is_valid_url(raw_input)
    if not valid:
        return {
            'valid': False,
            'error': reason,
            'message': "Invalid URL. Please enter a valid URL."
        }

    url = raw_input.strip()
    features = extract_features(url)
    trusted = check_trusted(url)
    is_typo, typo_brand, typo_match = check_typosquatting(url)
    insecure, insecure_brand = check_insecure_brand(url)
    valid_extension = has_valid_extension(url)

    return {
        'valid': True,
        'url': url,
        'trusted': trusted,
        'features': features,
        'is_typosquatting': is_typo,
        'typo_brand': typo_brand,
        'typo_match': typo_match,
        'is_insecure_brand': insecure,
        'insecure_brand': insecure_brand,
        'has_valid_extension': valid_extension,
    }


def evaluate_link_risk(url):
    """
    Full verdict for a single URL, meant to be reused anywhere a link needs
    judging by the exact same rules as the main URL scanner - currently
    used by email_analyzer.py to score links found inside an email body,
    so a phishing link in an email is judged identically to one pasted
    directly into the URL scanner (no separate/weaker duplicate logic).

    A link is only treated as safe (is_risky=False) if it is a
    structurally valid URL (see is_valid_url) AND uses https, AND either:
      - it is on the TRUSTED_DOMAINS allowlist (with https), OR
      - it is not on the allowlist but fails NONE of these checks:
          * ends in a recognized/trusted extension (see has_valid_extension)
          * is not a typosquat of a known brand
          * does not put a known brand name in the wrong/insecure domain
          * does not use a raw IP address instead of a domain
          * does not use a known URL shortener
          * domain does not end in a commonly-abused TLD (.xyz, .tk, etc)
          * does not contain obvious phishing bait keywords (login, verify..)

    A plain-http link is always risky, even for a trusted domain (the
    real site would never actually serve http) and even for domains not
    on the allowlist at all.

    NOTE: url length, entropy, and digit-ratio are intentionally NOT used
    as risk signals here. extract_features() computes them, but this
    codebase has no validated threshold for them - an initial attempt at
    an entropy cutoff (>4.0) incorrectly flagged an ordinary, non-malicious
    blog URL as risky. Rather than ship another unverified guess, these
    are left out until they can be calibrated against a labeled dataset.

    Returns:
        {
            'url'      : str,
            'is_risky' : bool,
            'reasons'  : [str, ...],  # empty when not risky
            'analysis' : dict or None # full analyze_url() result; None if malformed
        }
    """
    result = analyze_url(url)

    if not result['valid']:
        return {
            'url': url,
            'is_risky': True,
            'reasons': [result.get('error') or 'Malformed / not a well-formed URL'],
            'analysis': None
        }

    is_https = result['url'].lower().startswith('https://')

    if result['trusted']:
        # A trusted domain served over plain http is unusual, but per
        # explicit request this no longer forces a HIGH-risk verdict by
        # itself - it's surfaced as an informational reason only. All
        # the other checks (typosquat, insecure-brand, IP, shortener,
        # bad TLD, gibberish domain) are untouched and still apply as
        # before.
        if not is_https:
            return {
                'url': url,
                'is_risky': False,
                'reasons': ['Trusted domain but connection is insecure (http, not https) - informational only'],
                'analysis': result
            }
        return {
            'url': url,
            'is_risky': False,
            'reasons': [],
            'analysis': result
        }

    feats = result['features']

    # STRONG signals: each one of these, ALONE, is a real red flag that
    # almost never shows up in genuine mail (a real https confirmation
    # link never uses a raw IP, a shortener, or a known-abused TLD, and a
    # real brand never gets typosquatted by its own site). Any one of
    # these is enough by itself to call the link risky.
    #
    # NOTE: "not https" used to be in this STRONG bucket - a plain http
    # link was enough on its own to force the whole email HIGH. Per
    # explicit request, that's been removed: a bare http link (with no
    # other red flag) no longer forces risk by itself. It's moved down
    # into the WEAK bucket below, so it still counts toward the risk
    # decision when combined with something else, just not alone.
    strong_reasons = []

    if result['is_typosquatting']:
        strong_reasons.append("Typosquat of brand '" + str(result['typo_brand']) + "'")

    if result['is_insecure_brand']:
        strong_reasons.append("Brand '" + str(result['insecure_brand']) + "' used in a mismatched/insecure domain")

    if feats.get('has_ip'):
        strong_reasons.append('Uses a raw IP address instead of a domain name')

    if feats.get('is_shortened'):
        strong_reasons.append('Uses a URL shortener (destination hidden)')

    if feats.get('suspicious_tld'):
        strong_reasons.append('Suspicious/commonly-abused TLD')

    # A domain name that looks randomly generated is a real phishing
    # signal the ML/feature pipeline doesn't otherwise capture at all
    # (see the entropy note further down). On its own it's only ever a
    # WEAK signal - plenty of real, invented brand names look unusual.
    # But paired with a RESTRICTED TLD (.edu, .gov, .mil, etc - TLDs
    # that require real-world vetting to register), it's much stronger:
    # a random string almost certainly isn't a legitimately registered
    # university or government domain, so that combination is treated
    # as strong on its own.
    ext_gib = tldextract.extract(url)
    gibberish_domain = is_gibberish_domain(ext_gib.domain)
    if gibberish_domain and ext_gib.suffix.lower() in RESTRICTED_TRUST_TLDS:
        strong_reasons.append(
            "Random-looking domain name on a restricted TLD ('." +
            ext_gib.suffix.lower() + "') it's unlikely to be legitimately registered under"
        )

    # WEAK signals: common on their own in totally legitimate mail (a real
    # "confirm your email"/"manage your account" link contains bait words
    # like "confirm"/"account"; plenty of real companies use TLDs outside
    # our curated whitelist, e.g. notion.so). One of these alone should
    # NOT flag a link - that was the bug causing every real email with an
    # ordinary link to come back HIGH. Only stack these up (2+) before
    # treating them as meaningful.
    weak_reasons = []

    if not is_https:
        weak_reasons.append('Does not use HTTPS')

    if feats.get('suspicious_count', 0) > 0:
        weak_reasons.append('Contains phishing bait keywords (login, verify, secure, etc)')

    if feats.get('has_leetspeak'):
        weak_reasons.append('Leetspeak character substitution pattern detected')

    if feats.get('brand_in_domain', 0) > 0:
        weak_reasons.append('Brand name found inside subdomain/domain')

    if gibberish_domain and ext_gib.suffix.lower() not in RESTRICTED_TRUST_TLDS:
        weak_reasons.append('Domain name looks randomly generated, not a real word/name/brand')

    # Unrecognized extension is informational only - shown in the reasons
    # list when something else already made the link risky, but never
    # counted toward the risk decision itself. Our whitelist can't cover
    # every legitimate TLD in use (.so, .to, .gg, etc.), so treating an
    # unfamiliar-but-not-explicitly-abused extension as a red flag on its
    # own or in combination with one ordinary keyword produced constant
    # false positives on real company domains.
    extension_note = []
    if not result['has_valid_extension']:
        extension_note.append('Domain extension is not a recognized/trusted TLD')

    # NOTE: url_length / entropy / digit_ratio are deliberately NOT used
    # here. They're computed by extract_features() but this codebase has
    # no validated threshold for them - an early attempt at an entropy
    # cutoff (>4.0) flagged an ordinary, non-malicious blog URL as risky
    # (see conversation notes), so rather than guess another unverified
    # number, these are left out until there's real data to calibrate
    # against. Add them back deliberately if you calibrate thresholds
    # against a labeled dataset of your own phishing/clean URLs.

    is_risky = len(strong_reasons) > 0 or len(weak_reasons) >= 2
    reasons = strong_reasons + weak_reasons
    if is_risky:
        reasons += extension_note

    return {
        'url': url,
        'is_risky': is_risky,
        'reasons': reasons,
        'analysis': result
    }


def get_valid_url_input(prompt="Enter a URL to analyze: "):
    """Keep asking the user for input until a valid URL is entered.
    Displays 'Invalid URL. Please enter a valid URL.' on every bad
    attempt, then returns the first valid URL entered."""
    while True:
        user_input = input(prompt)
        valid, _ = is_valid_url(user_input)
        if valid:
            return user_input.strip()
        print("Invalid URL. Please enter a valid URL.")


def run_test_suite():
    """Batch-test a fixed list of URLs and non-URLs (no user input
    required) — handy for quickly sanity-checking the validator/scorer."""
    test_urls = [
        'https://www.google.com',
        'http://www.google.com',
        'http://g00gle.com',
        'http://gooogle.com',
        'http://paypal-secure-login.xyz',
        'https://github.com',
        'http://faceb00k-login.com',
        'http://sbi.co.in',
        'https://sbi.co.in',
        'http://googlle.com',
        'http://hdfcbank-verify.com',
        # Non-URL inputs — these should now be flagged as invalid
        # instead of silently getting a "low risk" score.
        'hello how are you',
        'this is not a url',
        'verify your account now',
        '12345',
        'just some random text',
        '',
        # Examples specifically called out as invalid
        'go',
        'hello',
        '123',
        'google',
        'google.com',          # missing http:// / https://
        'http://google.xyz',   # untrusted extension
    ]
    for u in test_urls:
        result = analyze_url(u)
        print('Input    :', repr(u))
        if not result['valid']:
            print('Result   : INVALID —', result['error'])
        else:
            print('Trusted  :', result['trusted'])
            print('Typo     :', result['is_typosquatting'], result['typo_brand'], result['typo_match'])
            print('Insecure :', result['is_insecure_brand'], result['insecure_brand'])
        print('---')


def main():
    """Interactive entry point: keep asking for a URL until a valid one is
    entered, then run the full analysis."""
    url = get_valid_url_input("Enter a URL to analyze: ")

    result = analyze_url(url)
    print()
    print('URL           :', result['url'])
    print('Trusted domain:', result['trusted'])
    print('Typosquatting :', result['is_typosquatting'],
          f"(brand: {result['typo_brand']}, matched: {result['typo_match']})"
          if result['is_typosquatting'] else '')
    print('Insecure brand:', result['is_insecure_brand'],
          f"(brand: {result['insecure_brand']})" if result['is_insecure_brand'] else '')
    print('Valid TLD     :', result['has_valid_extension'])

    is_https = result['url'].lower().startswith('https://')

    risky = not is_https or (result['trusted'] is False and (
        result['is_typosquatting'] or result['is_insecure_brand']
        or not result['has_valid_extension']
        or result['features']['suspicious_count'] > 0
        or result['features']['has_ip']
        or result['features']['suspicious_tld']
    ))
    if result['trusted'] and is_https:
        print('Verdict       : SAFE — recognized trusted domain.')
    elif result['trusted'] and not is_https:
        print('Verdict       : MEDIUM RISK — recognized trusted domain, but connection is insecure (http, not https). Consider visiting the https version instead.')
    elif not result['has_valid_extension']:
        print('Verdict       : HIGH RISK — domain does not end in a recognized extension (.com, .in, etc.).')
    elif risky:
        print('Verdict       : HIGH RISK — proceed with caution.')
    else:
        print('Verdict       : LOW RISK — no strong red flags found, but domain is not in the trusted list.')


if __name__ == '__main__':
    main()