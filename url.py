import re
from urllib.parse import urlparse
from datetime import timezone
# =========================================================
# DATABASES
# =========================================================

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".buzz",
    ".gq",
    ".tk",
    ".click",
    ".work",
    ".support"
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "rb.gy",
    "cutt.ly"
]

KNOWN_BRANDS = [
    "paypal",
    "microsoft",
    "google",
    "amazon",
    "apple",
    "netflix",
    "facebook",
    "instagram",
    "bank",
    "linkedin"
]

SUSPICIOUS_URL_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "banking",
    "confirm",
    "signin",
    "reset",
    "password"
]

COMMON_REPLACEMENTS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "@": "a",
    "$": "s"
}

# =========================================================
# URL EXTRACTION
# =========================================================

URL_REGEX = r'https?://[^\s]+'


def extract_urls(text):

    urls = re.findall(URL_REGEX, text)

    return urls


import whois
from datetime import datetime

# =========================================================
# DOMAIN AGE ANALYSIS
# =========================================================

def analyze_domain_age(domain):

    try:

        # =================================================
        # WHOIS LOOKUP
        # =================================================

        # domain_info = whois.whois(domain)
        domain_info = whois.whois(domain)

        creation_date = getattr(
            domain_info,
            "creation_date",
            None
        )
        current_date = datetime.now(
            timezone.utc
        )

        # =================================================
        # HANDLE MULTIPLE DATES
        # =================================================

        if isinstance(
            creation_date,
            list
        ):

            creation_date = creation_date[0]
            
        # =================================================
        # VALIDATION
        # =================================================

        if not creation_date:

            return {
                "domain_age_days": None,
                "risk_level": "UNKNOWN",
                "risk_score": 10,
                "reason":
                "Creation date unavailable"
            }

        # =================================================
        # CALCULATE AGE
        # =================================================

        current_date = datetime.now(
            timezone.utc
        )

        age = (
            current_date - creation_date
        ).days

        # =================================================
        # RISK CLASSIFICATION
        # =================================================

        if age < 30:

            risk_level = "HIGH"

            risk_score = 35

            reason = (
                "Very new domain"
            )

        elif age < 180:

            risk_level = "MEDIUM"

            risk_score = 20

            reason = (
                "Recently created domain"
            )

        elif age < 365:

            risk_level = "LOW"

            risk_score = 10

            reason = (
                "Relatively new domain"
            )

        else:

            risk_level = "MINIMAL"

            risk_score = 0

            reason = (
                "Old established domain"
            )

        return {

            "domain_age_days": age,

            "risk_level": risk_level,

            "risk_score": risk_score,

            "reason": reason
        }

    except Exception as e:

        return {

            "domain_age_days": None,

            "risk_level": "UNKNOWN",

            "risk_score": 10,

            "reason":
            f"WHOIS lookup failed: {e}"
        }
# =========================================================
# TYPO SQUATTING NORMALIZER
# =========================================================

def normalize_domain(domain):

    normalized = domain.lower()

    for fake_char, real_char in COMMON_REPLACEMENTS.items():

        normalized = normalized.replace(
            fake_char,
            real_char
        )

    return normalized


# =========================================================
# BRAND IMPERSONATION CHECK
# =========================================================

def detect_typosquatting(domain):

    normalized = normalize_domain(domain)

    detected_brands = []

    for brand in KNOWN_BRANDS:

        if brand in normalized and brand not in domain:
            detected_brands.append(brand)

    return detected_brands


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_single_url(url):

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    # =====================================================
    # HTTPS CHECK
    # =====================================================

    https_used = parsed.scheme == "https"

    # =====================================================
    # SUSPICIOUS TLD
    # =====================================================

    suspicious_tld = any(
        domain.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )

    # =====================================================
    # URL SHORTENER
    # =====================================================

    shortened_url = any(
        shortener in domain
        for shortener in SHORTENERS
    )

    # =====================================================
    # IP-BASED URL
    # =====================================================

    ip_based = bool(
        re.match(
            r'^\d+\.\d+\.\d+\.\d+$',
            domain
        )
    )

    # =====================================================
    # EXCESSIVE SUBDOMAINS
    # =====================================================

    subdomain_count = domain.count(".")

    excessive_subdomains = subdomain_count > 3

    # =====================================================
    # SUSPICIOUS URL KEYWORDS
    # =====================================================

    keyword_hits = [
        word for word
        in SUSPICIOUS_URL_KEYWORDS
        if word in url.lower()
    ]

    # =====================================================
    # TYPO SQUATTING
    # =====================================================

    typosquatting_brands = detect_typosquatting(domain)

    typosquatting_detected = len(
        typosquatting_brands
    ) > 0

    # =====================================================
    # LONG URL DETECTION
    # =====================================================

    long_url = len(url) > 100

    # =====================================================
    # RISK SCORING
    # =====================================================

    risk_score = 0

    if suspicious_tld:
        risk_score += 20

    if shortened_url:
        risk_score += 15

    if ip_based:
        risk_score += 25

    if excessive_subdomains:
        risk_score += 10

    if typosquatting_detected:
        risk_score += 30

    if keyword_hits:
        risk_score += 10

    if not https_used:
        risk_score += 5

    if long_url:
        risk_score += 5

    risk_score = min(risk_score, 100)

    # =====================================================
    # FINAL VERDICT
    # =====================================================

    if risk_score >= 80:
        verdict = "HIGH RISK"

    elif risk_score >= 50:
        verdict = "SUSPICIOUS"

    elif risk_score >= 25:
        verdict = "MODERATE RISK"

    else:
        verdict = "LOW RISK"

    # =====================================================
    # RETURN STRUCTURED OUTPUT
    # =====================================================

    return {
        "url": url,
        "domain": domain,
        "https_used": https_used,
        "suspicious_tld": suspicious_tld,
        "shortened_url": shortened_url,
        "ip_based": ip_based,
        "excessive_subdomains": excessive_subdomains,
        "subdomain_count": subdomain_count,
        "keyword_hits": keyword_hits,
        "typosquatting_detected": typosquatting_detected,
        "impersonated_brands": typosquatting_brands,
        "long_url": long_url,
        "risk_score": risk_score,
        "verdict": verdict
    }


# =========================================================
# MULTIPLE URL ANALYSIS
# =========================================================

def analyze_urls(text):

    urls = extract_urls(text)

    if not urls:

        return {
            "urls_found": False,
            "results": [],
            "total_urls": 0
        }

    results = []

    for url in urls:

        analysis = analyze_single_url(url)

        results.append(analysis)

    return {
        "urls_found": True,
        "total_urls": len(urls),
        "results": results
    }


# =========================================================
# TESTING
# =========================================================

if __name__ == "__main__":

    sample_text = """
    Your PayPal account has been suspended.

    Verify immediately:
    http://paypa1-security-login.xyz/verify

    Another link:
    https://bit.ly/security-check
    """

    output = analyze_urls(sample_text)

    from pprint import pprint

    pprint(output)