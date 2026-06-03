import re

# =========================================================
# SIGNAL DATABASES
# =========================================================

URGENCY_PHRASES = [
    "act now",
    "immediately",
    "urgent",
    "within 24 hours",
    "limited time",
    "verify now",
    "respond immediately",
    "update immediately",
    "click now",
    "instant action required"
]

FEAR_PHRASES = [
    "account suspended",
    "security breach",
    "unauthorized login",
    "your account is at risk",
    "payment failed",
    "legal action",
    "your account will be terminated",
    "suspicious activity detected",
    "account locked"
]

AUTHORITY_TERMS = [
    "bank",
    "paypal",
    "microsoft",
    "google",
    "government",
    "tax department",
    "hr team",
    "security team",
    "support team",
    "administrator"
]

FINANCIAL_BAIT = [
    "claim reward",
    "free money",
    "cash prize",
    "refund",
    "lottery winner",
    "gift card",
    "bonus",
    "exclusive offer",
    "claim now"
]

CREDENTIAL_TERMS = [
    "password",
    "otp",
    "cvv",
    "bank pin",
    "credit card",
    "debit card",
    "verification code",
    "security code",
    "account credentials"
]

# =========================================================
# TEXT NORMALIZATION
# =========================================================

def preprocess_text(text):

    text = text.lower()

    text = re.sub(r'\s+', ' ', text)

    return text.strip()


# =========================================================
# GENERIC SIGNAL DETECTOR
# =========================================================

def detect_signals(text, signal_list):

    detected = []

    for signal in signal_list:

        if signal in text:
            detected.append(signal)

    return detected


# =========================================================
# EXCESSIVE CAPITALIZATION
# =========================================================

def detect_excessive_caps(original_text):

    words = original_text.split()

    caps_words = [
        word for word in words
        if word.isupper() and len(word) > 3
    ]

    return caps_words


# =========================================================
# EXCESSIVE PUNCTUATION
# =========================================================

def detect_excessive_punctuation(text):

    exclamation_count = text.count("!")
    question_count = text.count("?")

    return (
        exclamation_count >= 3
        or question_count >= 3
    )


# =========================================================
# MAIN ANALYZER
# =========================================================

def analyze_social_engineering(text):

    original_text = text

    text = preprocess_text(text)

    # =====================================================
    # DETECT SIGNALS
    # =====================================================

    urgency_detected = detect_signals(
        text,
        URGENCY_PHRASES
    )

    fear_detected = detect_signals(
        text,
        FEAR_PHRASES
    )

    authority_detected = detect_signals(
        text,
        AUTHORITY_TERMS
    )

    financial_bait_detected = detect_signals(
        text,
        FINANCIAL_BAIT
    )

    credential_requests = detect_signals(
        text,
        CREDENTIAL_TERMS
    )

    excessive_caps = detect_excessive_caps(
        original_text
    )

    excessive_punctuation = (
        detect_excessive_punctuation(
            original_text
        )
    )

    # =====================================================
    # RISK SCORING
    # =====================================================

    risk_score = 0

    # Urgency
    risk_score += len(
        urgency_detected
    ) * 10

    # Fear
    risk_score += len(
        fear_detected
    ) * 10

    # Authority
    risk_score += len(
        authority_detected
    ) * 5

    # Financial bait
    risk_score += len(
        financial_bait_detected
    ) * 10

    # Credential requests
    risk_score += len(
        credential_requests
    ) * 20

    # Excessive capitalization
    risk_score += len(
        excessive_caps
    ) * 2

    # Excessive punctuation
    if excessive_punctuation:
        risk_score += 10

    risk_score = min(risk_score, 100)

    # =====================================================
    # FINAL VERDICT
    # =====================================================

    if risk_score >= 80:
        verdict = "HIGH RISK SOCIAL ENGINEERING"

    elif risk_score >= 50:
        verdict = "SUSPICIOUS MANIPULATION"

    elif risk_score >= 25:
        verdict = "MODERATE RISK"

    else:
        verdict = "LOW RISK"

    # =====================================================
    # ATTACK TECHNIQUES
    # =====================================================

    attack_techniques = []

    if urgency_detected:
        attack_techniques.append(
            "urgency manipulation"
        )

    if fear_detected:
        attack_techniques.append(
            "fear manipulation"
        )

    if authority_detected:
        attack_techniques.append(
            "authority impersonation"
        )

    if financial_bait_detected:
        attack_techniques.append(
            "financial bait"
        )

    if credential_requests:
        attack_techniques.append(
            "credential harvesting"
        )

    # =====================================================
    # RETURN STRUCTURED OUTPUT
    # =====================================================

    return {
        "urgency_detected": urgency_detected,
        "fear_detected": fear_detected,
        "authority_detected": authority_detected,
        "financial_bait_detected": financial_bait_detected,
        "credential_requests": credential_requests,
        "excessive_caps": excessive_caps,
        "excessive_punctuation": excessive_punctuation,
        "attack_techniques": attack_techniques,
        "risk_score": risk_score,
        "verdict": verdict
    }


# =========================================================
# TESTING
# =========================================================

if __name__ == "__main__":

    sample_text = '''
    URGENT!!!

    Your PayPal account has been suspended.

    Verify your password and OTP immediately
    within 24 hours to avoid legal action.

    Claim your refund now!!!
    '''

    result = analyze_social_engineering(
        sample_text
    )

    from pprint import pprint

    pprint(result)