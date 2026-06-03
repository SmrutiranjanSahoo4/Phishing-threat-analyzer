from url import analyze_urls, analyze_domain_age
from urllib.parse import urlparse

from social import (
    analyze_social_engineering
)

from llm import (
    llm_phishing_analysis
)

from aggregate import (
    aggregate_threat_analysis
)

from sender import (
    analyze_sender,
    extract_url_domain
)
# =========================================================
# MAIN PIPELINE
# =========================================================

def detect_phishing(message_text, sender_email=None):

    # =====================================================
    # URL ANALYSIS
    # =====================================================

    url_analysis = analyze_urls(
        message_text
    )
    # print(f"URL Analysis: {url_analysis}"
    # )
    ## =====================================================
    # DOMAIN AGE ANALYSIS
    # =====================================================

    domain_ages = []

    for item in url_analysis.get(
        "results",
        []
    ):

        url = item.get("url")

        if not url:
            continue

        domain = extract_url_domain(url)

        analysis = analyze_domain_age(
            domain
        )

        domain_ages.append({

            "url": url,

            "domain": domain,

            "analysis": analysis
        })

    # =====================================================
    # SOCIAL ENGINEERING ANALYSIS
    # =====================================================

    social_analysis = (
        analyze_social_engineering(
            message_text
        )
    )

    # =====================================================
    # SENDER ANALYSIS
    # =====================================================

    if sender_email:

        sender_analysis = analyze_sender(
            sender_email
        )

    else:

        sender_analysis = {
            "valid_email": False
        }

    # =====================================================
    # LLM THREAT REASONING
    # =====================================================

    llm_analysis = llm_phishing_analysis(

        email_text=message_text,

        url_analysis=url_analysis,

        social_analysis=social_analysis,
        sender_analysis=sender_analysis
    )

    # =====================================================
    # FINAL AGGREGATION
    # =====================================================

    final_report = (
        aggregate_threat_analysis(

            url_analysis,

            domain_ages,

            social_analysis,

            sender_analysis,

            llm_analysis
        )
    )

    # =====================================================
    # RETURN FINAL REPORT
    # =====================================================

    return final_report


# =========================================================
# TESTING
# =========================================================

if __name__ == "__main__":

    sample_message = '''

   Microsoft Security Alert

We detected unauthorized login attempts on your account.

Reset your password immediately:
http://micr0soft-security.xyz/reset

Failure to respond may result in permanent account lock.

    '''

    result = detect_phishing(
        sample_message
    )

    # =====================================================
    # PRINT RESULTS
    # =====================================================

    print("=" * 60)
    print("FINAL PHISHING ANALYSIS REPORT")
    print("=" * 60)

    print(
        f"Verdict: "
        f"{result['verdict']}"
    )

    print(
        f"Risk Score: "
        f"{result['risk_score']}/100"
    )

    print(
        f"Confidence: "
        f"{result['confidence']}%"
    )

    print("\nDomain Age Analysis:")

    for item in result[
        "domain_age_analysis"
    ]:

        analysis = item.get(
            "analysis",
            {}
        )

        print("\n----------------")

        print(
            f"Domain: "
            f"{item.get('domain')}"
        )

        print(
            f"Age: "
            f"{analysis.get('domain_age_days')} days"
        )

        print(
            f"Risk Level: "
            f"{analysis.get('risk_level')}"
        )

        print(
            f"Reason: "
            f"{analysis.get('reason')}"
        )
        
    print("Detected Attack Types:")

    for attack in result[
        "detected_attack_types"
    ]:

        print(f"- {attack}")

    print("Detected Issues:")

    for issue in result[
        "detected_issues"
    ]:

        print(f"- {issue}")

    print("LLM Threat Reasoning:")
    print(
        result.get(
            "llm_analysis",
            {}
        ).get(
            "reasoning",
            "No reasoning provided"
        )
    )

    print("Recommended Action:")

    print(
        result.get(
            "llm_analysis",
            {}
        ).get(
            "recommended_action",
            "No recommended action provided"
        )
    )

    print("=" * 60)