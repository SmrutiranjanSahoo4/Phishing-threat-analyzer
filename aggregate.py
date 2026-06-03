# =========================================================
# THREAT AGGREGATION ENGINE
# =========================================================
# from sender import sender
def aggregate_threat_analysis(
    url_analysis,
    domain_ages,
    social_analysis,
    sender_analysis,
    llm_analysis
):

    # =====================================================
    # INITIAL SCORES
    # =====================================================

    total_risk_score = 0

    detected_attack_types = set()

    detected_issues = []

    # =====================================================
    # URL RISK
    # =====================================================

    if url_analysis["urls_found"]:

        for result in url_analysis["results"]:

            total_risk_score += (
                result["risk_score"] * 0.4
            )

            # Suspicious TLD
            if result["suspicious_tld"]:

                detected_issues.append(
                    "Suspicious domain extension detected"
                )

            # Typosquatting
            if result["typosquatting_detected"]:

                detected_issues.append(
                    "Brand impersonation detected"
                )

                detected_attack_types.add(
                    "brand impersonation"
                )

            # IP-based URL
            if result["ip_based"]:

                detected_issues.append(
                    "IP-based URL detected"
                )

            # Shortened URL
            if result["shortened_url"]:

                detected_issues.append(
                    "Shortened URL detected"
                )

            # Excessive subdomains
            if result["excessive_subdomains"]:

                detected_issues.append(
                    "Excessive subdomains detected"
                )

    # =====================================================
    # DOMAIN AGE RISK
    # =====================================================

    if domain_ages:

        for domain_age in domain_ages:

            analysis = domain_age.get(
                "analysis",
                {}
            )

            total_risk_score += (
                analysis.get(
                    "risk_score",
                    0
                )
            )

            if (
                analysis.get(
                    "risk_level"
                ) == "HIGH"
            ):

                detected_issues.append(
                    "Very recently created domain detected"
                )

            elif (
                analysis.get(
                    "risk_level"
                ) == "MEDIUM"
            ):

                detected_issues.append(
                    "Recently created domain detected"
                )
    # =====================================================
    # SOCIAL ENGINEERING RISK
    # =====================================================

    social_risk = social_analysis["risk_score"]

    total_risk_score += (
        social_risk * 0.5
    )

    # Attack techniques
    for technique in social_analysis[
        "attack_techniques"
    ]:

        detected_attack_types.add(
            technique
        )

    # Credential harvesting
    if social_analysis[
        "credential_requests"
    ]:

        detected_issues.append(
            "Sensitive credential requests detected"
        )

    # Excessive capitalization
    if social_analysis[
        "excessive_caps"
    ]:

        detected_issues.append(
            "Excessive capitalization detected"
        )

    # Excessive punctuation
    if social_analysis[
        "excessive_punctuation"
    ]:

        detected_issues.append(
            "Excessive punctuation detected"
        )

    # =====================================================
    # SENDER ANALYSIS RISK
    # =====================================================

    if sender_analysis["valid_email"]:

        sender_risk = (
            sender_analysis["risk_score"]
        )

        total_risk_score += (
            sender_risk * 0.3
        )

        # Spoofing
        if sender_analysis[
            "spoofing_detected"
        ]:

            detected_issues.append(
                "Sender spoofing detected"
            )

            detected_attack_types.add(
                "sender impersonation"
            )

        # Free provider
        if sender_analysis[
            "free_email_provider"
        ]:

            detected_issues.append(
                "Free email provider used"
            )

        # Random chars
        if sender_analysis[
            "random_characters"
        ]:

            detected_issues.append(
                "Suspicious sender naming pattern"
            )
    # =====================================================
    # LLM THREAT LEVEL
    # =====================================================

    llm_threat = (
        llm_analysis["threat_level"]
        .lower()
    )

    if "high" in llm_threat:

        total_risk_score += 25

    elif "medium" in llm_threat:

        total_risk_score += 15

    elif "low" in llm_threat:

        total_risk_score += 10

    # =====================================================
    # NORMALIZATION
    # =====================================================

    total_risk_score = int(
        min(total_risk_score, 100)
    )

    # =====================================================
    # FINAL VERDICT
    # =====================================================

    if total_risk_score >= 80:

        verdict = (
            "HIGH-RISK PHISHING"
        )

    elif total_risk_score >= 60:

        verdict = (
            "LIKELY PHISHING"
        )

    elif total_risk_score >= 35:

        verdict = (
            "SUSPICIOUS MESSAGE"
        )

    else:

        verdict = "LOW RISK"

    # =====================================================
    # CONFIDENCE ESTIMATION
    # =====================================================

    confidence = min(
        100,
        50 + len(detected_issues) * 5
    )

    # =====================================================
    # RETURN STRUCTURED OUTPUT
    # =====================================================

    return {

        "verdict": verdict,

        "risk_score": total_risk_score,

        "confidence": confidence,

        "detected_attack_types": list(
            detected_attack_types
        ),

        "detected_issues": detected_issues,

        "url_analysis": url_analysis,

        "domain_age_analysis": domain_ages,

        "sender_analysis": sender_analysis,

        "social_engineering_analysis":
            social_analysis,

        "llm_analysis":
            llm_analysis
    }


# =========================================================
# TESTING
# =========================================================

if __name__ == "__main__":

    sample_url_analysis = {

        "urls_found": True,

        "results": [

            {
                "risk_score": 85,
                "suspicious_tld": True,
                "typosquatting_detected": True,
                "ip_based": False,
                "shortened_url": False,
                "excessive_subdomains": True
            }
        ]
    }

    sample_social_analysis = {

        "risk_score": 90,

        "attack_techniques": [

            "urgency manipulation",
            "credential harvesting"
        ],

        "credential_requests": [

            "password",
            "otp"
        ],

        "excessive_caps": [

            "URGENT"
        ],

        "excessive_punctuation": True
    }

    sample_llm_analysis = {

        "parsed_output": {

            "threat_level": "HIGH",

            "attack_techniques":
                "credential harvesting",

            "reasoning":
                "The message pressures the user into revealing credentials.",

            "recommended_action":
                "Do not click suspicious links."
        }
    }

    sample_domain_ages = [

        {
            "url": "http://example.com",

            "domain": "example.com",

            "analysis": {

                "domain_age_days": 30,

                "risk_level": "HIGH",

                "risk_score": 35,

                "reason":
                "Domain is very new"
            }
        }
    ]

    sample_sender_analysis = {

        "valid_email": True,

        "risk_score": 80,

        "spoofing_detected": True,

        "free_email_provider": False,

        "random_characters": True
    }

    result = aggregate_threat_analysis(

        sample_url_analysis,

        sample_domain_ages,

        sample_social_analysis,

        sample_sender_analysis,

        sample_llm_analysis
    )

    from pprint import pprint

    pprint(result)
   