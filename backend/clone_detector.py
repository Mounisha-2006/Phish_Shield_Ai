import requests
from bs4 import BeautifulSoup
import re
import tldextract
from urllib.parse import urlparse
from url_analyzer import levenshtein

KNOWN_BRANDS = {
    'paypal'     : 'paypal.com',
    'google'     : 'google.com',
    'facebook'   : 'facebook.com',
    'instagram'  : 'instagram.com',
    'amazon'     : 'amazon.com',
    'apple'      : 'apple.com',
    'microsoft'  : 'microsoft.com',
    'netflix'    : 'netflix.com',
    'twitter'    : 'twitter.com',
    'youtube'    : 'youtube.com',
    'linkedin'   : 'linkedin.com',
    'ebay'       : 'ebay.com',
    'whatsapp'   : 'whatsapp.com',
    'spotify'    : 'spotify.com',
    'dropbox'    : 'dropbox.com',
    'adobe'      : 'adobe.com',
    'reddit'     : 'reddit.com',
    'yahoo'      : 'yahoo.com',
    'wikipedia'  : 'wikipedia.org',
    'outlook'    : 'outlook.com',
    'gmail'      : 'gmail.com',
    'zoom'       : 'zoom.us',
    'slack'      : 'slack.com',
    'discord'    : 'discord.com',
    'telegram'   : 'telegram.org',
    'samsung'    : 'samsung.com',
    'oneplus'    : 'oneplus.com',
    'xiaomi'     : 'xiaomi.com',
    'oracle'     : 'oracle.com',
    'salesforce' : 'salesforce.com',
    'wordpress'  : 'wordpress.com',
    'cloudflare' : 'cloudflare.com',
    'mastercard' : 'mastercard.com',
    'visa'       : 'visa.com',
    'chase'      : 'chase.com',
    'wellsfargo' : 'wellsfargo.com',
    'hsbc'       : 'hsbc.com',
    'stripe'     : 'stripe.com',
    'booking'    : 'booking.com',
    'airbnb'     : 'airbnb.com',
    'uber'       : 'uber.com',
    'flipkart'   : 'flipkart.com',
    'myntra'     : 'myntra.com',
    'ajio'       : 'ajio.com',
    'meesho'     : 'meesho.com',
    'swiggy'     : 'swiggy.com',
    'zomato'     : 'zomato.com',
    'makemytrip' : 'makemytrip.com',
    'oyorooms'   : 'oyorooms.com',
    'irctc'      : 'irctc.co.in',
    'sbi'        : 'sbi.co.in',
    'hdfcbank'   : 'hdfcbank.com',
    'icicibank'  : 'icicibank.com',
    'axisbank'   : 'axisbank.com',
    'pnbindia'   : 'pnbindia.in',
    'kotak'      : 'kotak.com',
    'paytm'      : 'paytm.com',
    'phonepe'    : 'phonepe.com',
    'uidai'      : 'uidai.gov.in',
    'incometax'  : 'incometax.gov.in',
}

# Some large consumer/tech brands legitimately operate their own real
# websites on multiple country-code TLDs (Google India = google.co.in,
# Amazon UK = amazon.co.uk, etc). Without this, the full-domain-match fix
# below would correctly catch phishing tricks like "paypal.xyz" but would
# ALSO falsely flag these genuine regional sites as brand impersonation.
#
# This leniency is deliberately NOT extended to financial/payment/
# government brands (PayPal, the banks, Paytm, UIDAI, IRCTC, etc) - those
# are higher-value phishing targets that in practice only operate on ONE
# real domain, so for them "brand word + a different TLD" should always
# stay suspicious rather than be assumed legitimate. Keep this list
# conservative and only add a domain here once you've actually confirmed
# it's real - an incorrect entry here would create a genuine blind spot.
REGIONAL_BRAND_DOMAINS = {
    'google'    : ['google.co.in', 'google.co.uk', 'google.de', 'google.ca',
                   'google.com.au', 'google.co.jp', 'google.fr', 'google.it',
                   'google.es', 'google.com.br'],
    'amazon'    : ['amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.ca',
                   'amazon.com.au', 'amazon.co.jp', 'amazon.fr', 'amazon.it',
                   'amazon.es', 'amazon.com.br'],
    'ebay'      : ['ebay.co.uk', 'ebay.in', 'ebay.de', 'ebay.ca', 'ebay.com.au'],
}


def _build_legit_domain_lookup():
    """Maps every domain we consider genuinely brand-owned (the single
    canonical domain from KNOWN_BRANDS, plus any approved regional
    variants above) back to which brand owns it. Used everywhere the
    code needs to answer "is THIS domain actually this brand's real
    site", instead of the old, unsafe "does the brand word appear before
    the dot, regardless of TLD" check."""
    lookup = {}
    for brand, real_domain in KNOWN_BRANDS.items():
        lookup[real_domain] = brand
    for brand, domains in REGIONAL_BRAND_DOMAINS.items():
        for d in domains:
            lookup[d] = brand
    return lookup


LEGIT_DOMAIN_TO_BRAND = _build_legit_domain_lookup()


def get_page_info(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(url, timeout=6, headers=headers)
        soup = BeautifulSoup(resp.text, 'html.parser')
        title  = soup.title.string.strip().lower() if soup.title else ''
        forms  = len(soup.find_all('form'))
        inputs = len(soup.find_all('input'))
        return {
            'title'      : title,
            'forms'      : forms,
            'inputs'     : inputs,
            'status'     : resp.status_code,
            'fetch_error': None
        }
    except requests.exceptions.SSLError as e:
        return {'fetch_error': 'ssl_error', 'detail': str(e)}
    except requests.exceptions.Timeout as e:
        return {'fetch_error': 'timeout', 'detail': str(e)}
    except requests.exceptions.RequestException as e:
        return {'fetch_error': 'connection_error', 'detail': str(e)}
    except Exception as e:
        # Page loaded but something else went wrong (e.g. malformed HTML
        # broke parsing). Still a failure to verify, not a green light.
        return {'fetch_error': 'parse_error', 'detail': str(e)}

def detect_clone(url):
    url = url.strip()  # remove leading/trailing whitespace - a stray space
                        # before "http://" breaks tldextract's domain parsing
    alerts   = []
    findings = []
    impersonated_brand = None

    ext      = tldextract.extract(url)
    domain   = ext.domain + '.' + ext.suffix
    domain   = domain.lower()
    full_url = url.lower()

    # Guard - reject anything that isn't actually a real, well-formed URL
    # BEFORE running any of the checks below. Plain text like "home" or
    # "go" (with or without a scheme prepended) has no recognized TLD, so
    # tldextract leaves ext.suffix empty - that's a reliable signal there
    # is no real domain here at all, not something worth scoring as
    # low-risk. This check is self-contained (doesn't depend on the
    # Flask route validating first) so this function is safe to call
    # directly, e.g. from scripts or the __main__ block below.
    parsed = urlparse(url if '://' in url else 'http://' + url)
    has_scheme = '://' in url and parsed.scheme in ('http', 'https')
    if not has_scheme or not ext.suffix:
        return {
            "url"          : url,
            "domain"       : None,
            "valid"        : False,
            "is_clone"     : False,
            "threat_level" : None,
            "confidence"   : None,
            "alerts"       : [],
            "findings"     : [{
                'check'  : 'URL Validation',
                'result' : 'Not a valid, well-formed URL with a real domain extension',
                'risk'   : 'INFO'
            }],
            "impersonated_brand": None
        }

    # Confirmed real brand domain (any subdomain, e.g. accounts.google.com)
    # — this IS the actual brand's own domain, so there's zero
    # *impersonation* risk (is_clone stays False). However that's a
    # separate question from whether the connection itself is safe: a
    # plain-http URL is never treated as safe here, even for a
    # confirmed-real domain, since http traffic (including any credentials
    # a user might enter) isn't encrypted. `parsed` was already computed
    # above during URL validation and is guaranteed to have a real
    # 'http'/'https' scheme at this point (the earlier guard returns
    # first otherwise).
    #
    # IMPORTANT: this must check the FULL domain+suffix against the real
    # domain on record (e.g. "paypal.com"), not just whether the brand
    # WORD appears before the dot. Checking only `ext.domain` (e.g.
    # "paypal") ignores the TLD entirely, so "paypal.xyz" or "paypal.tk"
    # would incorrectly match "paypal" and be waved through as the real
    # site - exactly the classic same-word-wrong-extension phishing
    # trick this tool exists to catch. Subdomains are still allowed
    # (accounts.google.com -> domain='google.com', matches fine) since
    # `domain` already strips the subdomain before this comparison.
    if domain in LEGIT_DOMAIN_TO_BRAND:
        is_insecure_http = (parsed.scheme == 'http')
        findings = [{
            'check'  : 'Brand Verification',
            'result' : "Domain confirmed as official " + ext.domain.upper() + " domain",
            'risk'   : 'INFO'
        }]
        alerts = []
        if is_insecure_http:
            alerts.append("Insecure connection - site uses HTTP instead of HTTPS")
            findings.append({
                'check'  : 'Protocol Security',
                'result' : 'URL uses HTTP (unencrypted) instead of HTTPS - not safe for login/payment pages',
                'risk'   : 'MEDIUM'
            })
        return {
            "url"          : url,
            "domain"       : domain,
            "is_clone"     : False,
            "threat_level" : "MEDIUM" if is_insecure_http else "LOW",
            "confidence"   : 40.0 if is_insecure_http else 0.0,
            "alerts"       : alerts,
            "findings"     : findings,
            "impersonated_brand": None
        }

    # Check 0 - Insecure protocol (HTTP instead of HTTPS)
    # `parsed` was already computed above during URL validation, and by
    # this point has_scheme is guaranteed True (the guard above returns
    # early otherwise), so parsed.scheme reliably reflects what the user
    # actually typed - 'http' or 'https'.
    is_insecure_http = (parsed.scheme == 'http')
    if is_insecure_http:
        alerts.append("Insecure connection - site uses HTTP instead of HTTPS")
        findings.append({
            'check'  : 'Protocol Security',
            'result' : 'URL uses HTTP (unencrypted) instead of HTTPS - not safe for login/payment pages',
            'risk'   : 'HIGH'
        })

    # Check 1 - Suspicious TLDs
    bad_tlds = ['.tk','.ml','.ga','.cf','.xyz','.top','.club','.work']
    for t in bad_tlds:
        if url.endswith(t):
            alerts.append("Suspicious domain extension detected")
            findings.append({
                'check'  : 'Domain Extension',
                'result' : 'Suspicious TLD found',
                'risk'   : 'HIGH'
            })
            break

    # Check 2 - Brand name in wrong domain
    # Compare the FULL registrable domain+TLD (e.g. "paypal.com") against
    # the brand's real known domain - not just the bare word before the
    # dot. Checking only the word (ext.domain == brand) would incorrectly
    # treat "paypal.xyz" or "paypal.tk" as "the real owner" just because
    # the word "paypal" appears before ANY extension, letting the classic
    # same-brand-wrong-TLD phishing trick slip through undetected.
    for brand, real_domain in KNOWN_BRANDS.items():
        brand_is_real_owner = (LEGIT_DOMAIN_TO_BRAND.get(domain) == brand)
        if brand_is_real_owner:
            continue  # this IS the real brand's domain - not a clone
        if brand in ext.domain.lower():
            # brand name appears as PART of a different domain, e.g.
            # "google-secure-login.xyz" -> ext.domain = "google-secure-login"
            # (this also now correctly catches "paypal.xyz" since ext.domain
            # is "paypal" but domain "paypal.xyz" != real_domain "paypal.com")
            impersonated_brand = brand
            msg = "Brand " + brand.upper() + " found but domain is not " + real_domain
            alerts.append(msg)
            res = "Claims to be " + brand.upper() + " but domain is " + domain
            findings.append({
                'check'  : 'Brand Impersonation',
                'result' : res,
                'risk'   : 'HIGH'
            })

    # Check 3 - Hyphens in domain
    hyphen_count = ext.domain.count('-')
    if hyphen_count >= 2:
        alerts.append("Multiple hyphens in domain - phishing pattern")
        res = ext.domain + " has " + str(hyphen_count) + " hyphens"
        findings.append({
            'check'  : 'Domain Pattern',
            'result' : res,
            'risk'   : 'MEDIUM'
        })

    # Check 5 - Fuzzy typosquat match against known brands (catches
    # leetspeak/misspellings like "g00gle" or "paypa1" that don't contain
    # the exact brand string, so Check 2's plain substring match misses
    # them). Uses the same edit-distance logic as url_analyzer.py.
    domain_part = ext.domain.lower()
    for brand in KNOWN_BRANDS:
        if domain_part == brand:
            continue  # exact match already handled by the early return above
        max_allowed = 1 if len(brand) <= 5 else 2
        distance = levenshtein(domain_part, brand)
        if 0 < distance <= max_allowed:
            if not impersonated_brand:
                impersonated_brand = brand
            msg = "Domain '" + domain_part + "' closely resembles brand " + brand.upper() + " (possible typosquat)"
            alerts.append(msg)
            findings.append({
                'check'  : 'Typosquat Pattern',
                'result' : "'" + domain_part + "' is " + str(distance) + " character(s) from '" + brand + "'",
                'risk'   : 'HIGH'
            })
            break  # one typosquat match is enough, avoid duplicate findings

    # Check 4 - Fetch page
    page = get_page_info(url)
    if page.get('fetch_error'):
        # Could NOT verify the live page content - this is not the same
        # thing as "checked it and it's clean". A failed fetch (bad/self
        # -signed cert, timeout, connection refused, blocked scanner,
        # malformed response, etc.) gives zero evidence either way, so it
        # must not be treated as equivalent to a verified-safe page.
        reason_text = {
            'ssl_error'       : 'SSL/certificate error while connecting',
            'timeout'         : 'Connection timed out',
            'connection_error': 'Could not connect to the site',
            'parse_error'     : 'Page loaded but content could not be parsed',
        }.get(page['fetch_error'], 'Could not verify page content')
        findings.append({
            'check'  : 'Page Verification',
            'result' : reason_text + " - unable to confirm this page is not a clone",
            'risk'   : 'MEDIUM'
        })
    elif page['status'] == 200:
        for brand in KNOWN_BRANDS:
            brand_is_real_owner = (LEGIT_DOMAIN_TO_BRAND.get(domain) == brand)
            if brand in page['title'] and not brand_is_real_owner:
                msg = "Page title mentions " + brand + " but domain is different"
                alerts.append(msg)
                res = "Title contains " + brand + " on unverified domain"
                findings.append({
                    'check'  : 'Page Title',
                    'result' : res,
                    'risk'   : 'HIGH'
                })

        if page['forms'] > 0 and page['inputs'] > 1:
            res = str(page['forms']) + " form with " + str(page['inputs']) + " inputs found"
            findings.append({
                'check'  : 'Login Form',
                'result' : res,
                'risk'   : 'MEDIUM'
            })

        res = "Page loaded OK HTTP " + str(page['status'])
        findings.append({
            'check'  : 'Page Status',
            'result' : res,
            'risk'   : 'INFO'
        })
    else:
        # Page responded but with a non-200 status (blocked, forbidden,
        # redirected, error, etc). The returned content (if any) isn't
        # reliable for brand/title checks, so we skip those and just note
        # the status rather than risk a false positive from an error page.
        res = "Page responded with HTTP " + str(page['status']) + " - could not verify content"
        findings.append({
            'check'  : 'Page Status',
            'result' : res,
            'risk'   : 'INFO'
        })

    # Calculate risk
    high_count   = sum(1 for f in findings if f['risk'] == 'HIGH')
    medium_count = sum(1 for f in findings if f['risk'] == 'MEDIUM')

    if high_count >= 2:
        threat_level = "HIGH"
        confidence   = min(97, 75 + high_count * 7)
    elif high_count == 1 or medium_count >= 2:
        threat_level = "MEDIUM"
        confidence   = 60 + medium_count * 5
    else:
        threat_level = "LOW"
        confidence   = 25

    # Insecure protocol always escalates to HIGH regardless of what the
    # count-based scoring above landed on - per project requirement, a
    # plain-http URL is never treated as safe/low-risk, even if none of
    # the other brand/TLD/typosquat checks fired.
    if is_insecure_http and threat_level != "HIGH":
        threat_level = "HIGH"
        confidence   = max(confidence, 75)

    # If the live page could not be fetched/verified at all (SSL error,
    # timeout, blocked, etc.), we have NO evidence this page is clean -
    # an unverifiable page must never land on LOW/safe just because none
    # of the URL-text checks happened to fire. This does not downgrade an
    # already-HIGH verdict from another check, only raises an unverified
    # LOW up to MEDIUM.
    if page.get('fetch_error') and threat_level == "LOW":
        threat_level = "MEDIUM"
        confidence   = max(confidence, 45)

    return {
        "url"          : url,
        "domain"       : domain,
        "is_clone"     : len(alerts) > 0,
        "threat_level" : threat_level,
        "confidence"   : round(confidence, 2),
        "alerts"       : alerts,
        "findings"     : findings,
        "impersonated_brand": impersonated_brand
    }


if __name__ == "__main__":
    print("Testing clone detector...\n")

    print("Test 1 - Fake PayPal URL:")
    r1 = detect_clone("http://paypal-secure-login.xyz")
    print("  Is Clone     : " + str(r1['is_clone']))
    print("  Threat Level : " + r1['threat_level'])
    print("  Confidence   : " + str(r1['confidence']) + "%")
    print("  Alerts:")
    for a in r1['alerts']:
        print("    - " + a)

    print()

    print("Test 2 - Real Google:")
    r2 = detect_clone("https://www.google.com")
    print("  Is Clone     : " + str(r2['is_clone']))
    print("  Threat Level : " + r2['threat_level'])
    print("  Confidence   : " + str(r2['confidence']) + "%")
    if r2['alerts']:
        for a in r2['alerts']:
            print("    - " + a)
    else:
        print("  Alerts       : None")

    print("\n✅ Clone detector working!")