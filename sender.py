import re

# =========================================================
# DATABASES
# =========================================================

FREE_EMAIL_PROVIDERS = [

    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "hotmail.com",
    "protonmail.com"
]

KNOWN_BRANDS = [

    "paypal",
    "microsoft",
    "google",
    "amazon",
    "apple",
    "linkedin",
    "netflix",
    "bank"
]

SUSPICIOUS_KEYWORDS = [

    "security",
    "support",
    "verify",
    "update",
    "alert",
    "billing",
    "admin",
    "helpdesk"
]

COMMON_REPLACEMENTS = {

    "0": "o",
    "1": "l",
    "3": "e",
    "@": "a",
    "$": "s"
}

# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_REGEX = r'^[^@]+@[^@]+\.[^@]+$'


def is_valid_email(email):

    return bool(
        re.match(
            EMAIL_REGEX,
            email
        )
    )

# =========================================================
# NORMALIZATION
# =========================================================

def normalize_text(text):

    text = text.lower()

    for fake, real in COMMON_REPLACEMENTS.items():

        text = text.replace(
            fake,
            real
        )

    return text

# =========================================================
# DOMAIN EXTRACTION
# =========================================================

def extract_email_domain(email):

    return email.split("@")[-1].lower()

from urllib.parse import urlparse

# =====================================================
# URL DOMAIN EXTRACTION
# =====================================================

def extract_url_domain(url):

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    domain = domain.replace(
        "www.",
        ""
    )

    return domain
# =========================================================
# USERNAME EXTRACTION
# =========================================================

def extract_username(email):

    return email.split("@")[0].lower()

# =========================================================
# BRAND IMPERSONATION DETECTION
# =========================================================

def detect_brand_impersonation(email):

    normalized = normalize_text(email)

    detected_brands = []

    for brand in KNOWN_BRANDS:

        if brand in normalized:

            actual_domain = extract_email_domain(
                email
            )

            # Legitimate brand domain check
            if brand not in actual_domain:

                detected_brands.append(
                    brand
                )

    return detected_brands

# =========================================================
# RANDOM CHARACTER DETECTION
# =========================================================

def detect_random_characters(username):

    suspicious_patterns = [

        r'\d{3,}',         # many numbers
        r'[a-zA-Z]{1}\d[a-zA-Z]\d',
        r'[_\-]{2,}'
    ]

    for pattern in suspicious_patterns:

        if re.search(pattern, username):

            return True

    return False

# =========================================================
# SUSPICIOUS KEYWORD DETECTION
# =========================================================

def detect_suspicious_keywords(username):

    detected = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in username:

            detected.append(keyword)

    return detected

# =========================================================
# MAIN ANALYZER
# =========================================================

def analyze_sender(sender_email):

    # =====================================================
    # VALIDATION
    # =====================================================

    if not is_valid_email(sender_email):

        return {

            "valid_email": False,
            "error": "Invalid email format"
        }

    # =====================================================
    # EXTRACTION
    # =====================================================

    sender_email = sender_email.lower()

    domain = extract_email_domain(
        sender_email
    )

    username = extract_username(
        sender_email
    )

    # =====================================================
    # FREE EMAIL PROVIDER
    # =====================================================

    free_provider = (
        domain in FREE_EMAIL_PROVIDERS
    )

    # =====================================================
    # BRAND IMPERSONATION
    # =====================================================

    impersonated_brands = (
        detect_brand_impersonation(
            sender_email
        )
    )

    spoofing_detected = (
        len(impersonated_brands) > 0
    )

    # =====================================================
    # RANDOM CHARACTERS
    # =====================================================

    random_characters = (
        detect_random_characters(
            username
        )
    )

    # =====================================================
    # SUSPICIOUS KEYWORDS
    # =====================================================

    suspicious_keywords = (
        detect_suspicious_keywords(
            username
        )
    )

    # =====================================================
    # RISK SCORING
    # =====================================================

    risk_score = 0

    # Brand impersonation
    if spoofing_detected:

        risk_score += 40

    # Free email provider
    if free_provider:

        risk_score += 15

    # Random characters
    if random_characters:

        risk_score += 15

    # Suspicious keywords
    risk_score += (
        len(suspicious_keywords) * 10
    )

    risk_score = min(
        risk_score,
        100
    )

    # =====================================================
    # FINAL VERDICT
    # =====================================================

    if risk_score >= 75:

        verdict = "HIGH-RISK SENDER"

    elif risk_score >= 45:

        verdict = "SUSPICIOUS SENDER"

    elif risk_score >= 20:

        verdict = "MODERATE RISK"

    else:

        verdict = "LOW RISK"

    # =====================================================
    # RETURN STRUCTURED OUTPUT
    # =====================================================

    return {

        "valid_email": True,

        "sender_email": sender_email,

        "domain": domain,

        "username": username,

        "free_email_provider":
            free_provider,

        "spoofing_detected":
            spoofing_detected,

        "impersonated_brands":
            impersonated_brands,

        "random_characters":
            random_characters,

        "suspicious_keywords":
            suspicious_keywords,

        "risk_score":
            risk_score,

        "verdict":
            verdict
    }

# =========================================================
# TESTING
# =========================================================

if __name__ == "__main__":

    sample_sender = (
        "paypa1-security-alert@gmail.com"
    )

    result = analyze_sender(
        sample_sender
    )

    from pprint import pprint

    pprint(result)