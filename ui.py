import streamlit as st
import json

from Langchain.Project.phising_analysis.main import detect_phishing

# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="AI Phishing Threat Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown(
    """
    <style>

    .main {
        padding-top: 1rem;
    }

    .title {
        font-size: 42px;
        font-weight: bold;
        color: #00C2FF;
    }

    .subtitle {
        font-size: 18px;
        color: #B0BEC5;
        margin-bottom: 20px;
    }

    .risk-high {
        color: #ff4b4b;
        font-weight: bold;
    }

    .risk-medium {
        color: #ffb703;
        font-weight: bold;
    }

    .risk-low {
        color: #4caf50;
        font-weight: bold;
    }

    </style>
    """,
    unsafe_allow_html=True
)

# =========================================================
# HEADER
# =========================================================

st.markdown(
    '<div class="title">🛡️ AI Phishing Threat Analyzer</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">Explainable AI-powered phishing detection and threat intelligence system</div>',
    unsafe_allow_html=True
)

# =========================================================
# SESSION STATE
# =========================================================

if "reset_counter" not in st.session_state:
    st.session_state.reset_counter = 0

# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.header("⚙️ System Overview")

    st.markdown(
        """
### Detection Modules
- URL Risk Analysis
- Sender Spoofing Detection
- Social Engineering Analysis
- Credential Harvesting Detection
- Domain Age Analysis
- LLM Threat Reasoning
- Threat Aggregation Engine

### AI Model
- Mistral Small

### Security Features
- Typosquatting Detection
- Suspicious TLD Analysis
- Attack Technique Detection
- Explainable Threat Reasoning
"""
    )

    st.divider()

    if st.button("🗑️ Clear Results"):

        st.session_state["sender_email"] = ""
        st.session_state["message_input"] = ""

        st.session_state.reset_counter += 1

        keys_to_remove = [
            key for key in st.session_state.keys()
            if key not in [
                "sender_email",
                "message_input",
                "reset_counter"
            ]
        ]

        for key in keys_to_remove:
            del st.session_state[key]

        st.rerun()

# =========================================================
# INPUT SECTION
# =========================================================

col1, col2 = st.columns([1.2, 1])

with col1:

    st.markdown("## 📥 Input Threat Content")

    sender_email = st.text_input(
        "Sender Email (Optional)",
        placeholder="example@domain.com",
        key="sender_email"
    )

    message_input = st.text_area(
        "Paste phishing email or suspicious message",
        height=350,
        placeholder="Paste suspicious email, SMS, or phishing content here...",
        key="message_input"
    )

    analyze_button = st.button(
        "🔍 Analyze Threat",
        use_container_width=True
    )

# =========================================================
# ANALYSIS
# =========================================================

if analyze_button:

    if not message_input.strip():

        st.warning(
            "Please enter message content."
        )

        st.stop()

    # =====================================================
    # MAIN DETECTION
    # =====================================================

    with st.spinner(
        "Analyzing phishing threat..."
    ):

        result = detect_phishing(
            message_input,
            sender_email
        )

    # =====================================================
    # FINAL DASHBOARD
    # =====================================================

    with col2:

        st.markdown(
            "## 🚨 Threat Assessment"
        )

        verdict = result["verdict"]

        risk_score = result["risk_score"]

        confidence = result["confidence"]

        # =================================================
        # COLOR-CODED VERDICT
        # =================================================

        if "HIGH" in verdict:

            st.error(f"### {verdict}")

        elif "LIKELY" in verdict:

            st.warning(f"### {verdict}")

        elif "SUSPICIOUS" in verdict:

            st.warning(f"### {verdict}")

        else:

            st.success(f"### {verdict}")

        metric1, metric2 = st.columns(2)

        with metric1:

            st.metric(
                "Risk Score",
                f"{risk_score}/100"
            )

        with metric2:

            st.metric(
                "Confidence",
                f"{confidence}%"
            )

        st.divider()

        # =================================================
        # ATTACK TYPES
        # =================================================

        st.markdown(
            "### ⚠️ Attack Techniques"
        )

        if result[
            "detected_attack_types"
        ]:

            for attack in result[
                "detected_attack_types"
            ]:

                st.warning(attack)

        else:

            st.success(
                "No attack techniques detected"
            )

        st.divider()

        # =================================================
        # DETECTED ISSUES
        # =================================================

        st.markdown(
            "### 🚩 Detected Issues"
        )

        if result[
            "detected_issues"
        ]:

            for issue in result[
                "detected_issues"
            ]:

                st.error(issue)

        else:

            st.success(
                "No major issues detected"
            )

    # =====================================================
    # TABS
    # =====================================================

    tab1, tab2, tab3, tab4, tab5 = st.tabs([

        "🧠 Summary",

        "🌐 URL Analysis",

        "👤 Sender Analysis",

        "🎭 Social Engineering",

        "🤖 AI Reasoning",

        # "📄 Raw JSON"
    ])

    # =====================================================
    # SUMMARY TAB
    # =====================================================

    with tab1:

        st.markdown(
            "## 🧠 Threat Summary"
        )

        st.write(
            result["llm_analysis"]
            ["reasoning"]
        )

        st.divider()

        st.markdown(
            "## 🛡️ Recommended Action"
        )

        st.info(
            result["llm_analysis"]
            ["recommended_action"]
        )

        st.divider()

        st.markdown(
            "## 📊 Threat Score Contributors"
        )

        contributors = []

        if result[
            "sender_analysis"
        ].get(
            "spoofing_detected"
        ):

            contributors.append(
                "+30 → Sender Spoofing"
            )

        if result[
            "social_engineering_analysis"
        ].get(
            "credential_requests"
        ):

            contributors.append(
                "+20 → Credential Harvesting"
            )

        if result[
            "url_analysis"
        ]["urls_found"]:

            contributors.append(
                "+15 → Suspicious URL"
            )

        if result[
            "social_engineering_analysis"
        ].get(
            "urgency_detected"
        ):

            contributors.append(
                "+10 → Urgency Manipulation"
            )

        for item in contributors:

            st.warning(item)

    # =====================================================
    # URL ANALYSIS TAB
    # =====================================================

    with tab2:

        st.markdown(
            "## 🌐 URL Security Analysis"
        )

        url_analysis = result[
            "url_analysis"
        ]

        if not url_analysis[
            "urls_found"
        ]:

            st.info(
                "No URLs detected."
            )

        else:

            for idx, item in enumerate(
                url_analysis["results"],
                start=1
            ):

                with st.expander(
                    f"URL {idx}"
                ):

                    st.write(
                        f"**URL:** {item['url']}"
                    )

                    st.write(
                        f"**Domain:** {item['domain']}"
                    )

                    st.metric(
                        "URL Risk Score",
                        f"{item['risk_score']}/100"
                    )

                    st.write(
                        f"**Verdict:** {item['verdict']}"
                    )

                    st.divider()

                    if item[
                        "suspicious_tld"
                    ]:

                        st.error(
                            "Suspicious domain extension detected"
                        )

                    if item[
                        "typosquatting_detected"
                    ]:

                        st.error(
                            "Brand impersonation detected"
                        )

                    if item[
                        "ip_based"
                    ]:

                        st.error(
                            "IP-based URL detected"
                        )

                    if item[
                        "shortened_url"
                    ]:

                        st.warning(
                            "Shortened URL detected"
                        )

                    if item[
                        "keyword_hits"
                    ]:

                        st.markdown(
                            "### Suspicious Keywords"
                        )

                        for keyword in item[
                            "keyword_hits"
                        ]:

                            st.warning(keyword)

        # =================================================
        # DOMAIN AGE
        # =================================================

        st.divider()

        st.markdown(
            "## ⏳ Domain Age Analysis"
        )

        for domain_item in result[
            "domain_age_analysis"
        ]:

            analysis = domain_item[
                "analysis"
            ]

            with st.expander(
                domain_item["domain"]
            ):

                age = analysis.get(
                    "domain_age_days"
                )

                if age is None:

                    st.warning(
                        "Domain age unavailable"
                    )

                else:

                    st.metric(
                        "Domain Age",
                        f"{age} days"
                    )

                st.write(
                    f"**Risk Level:** {analysis.get('risk_level')}"
                )

                st.write(
                    f"**Reason:** {analysis.get('reason')}"
                )

    # =====================================================
    # SENDER ANALYSIS TAB
    # =====================================================

    with tab3:

        st.markdown(
            "## 👤 Sender Analysis"
        )

        sender = result[
            "sender_analysis"
        ]

        if not sender.get(
            "valid_email"
        ):

            st.info(
                "No sender email provided."
            )

        else:

            st.metric(
                "Sender Risk Score",
                f"{sender['risk_score']}/100"
            )

            st.write(
                f"**Sender:** {sender['sender_email']}"
            )

            st.write(
                f"**Domain:** {sender['domain']}"
            )

            st.write(
                f"**Verdict:** {sender['verdict']}"
            )

            st.divider()

            if sender[
                "spoofing_detected"
            ]:

                st.error(
                    "Brand impersonation detected"
                )

            if sender[
                "free_email_provider"
            ]:

                st.warning(
                    "Free email provider used"
                )

            if sender[
                "random_characters"
            ]:

                st.warning(
                    "Suspicious sender naming pattern"
                )

            if sender[
                "impersonated_brands"
            ]:

                st.markdown(
                    "### Impersonated Brands"
                )

                for brand in sender[
                    "impersonated_brands"
                ]:

                    st.error(brand)

    # =====================================================
    # SOCIAL ENGINEERING TAB
    # =====================================================

    with tab4:

        st.markdown(
            "## 🎭 Social Engineering Analysis"
        )

        social = result[
            "social_engineering_analysis"
        ]

        st.metric(
            "Manipulation Risk Score",
            f"{social['risk_score']}/100"
        )

        st.write(
            f"**Verdict:** {social['verdict']}"
        )

        st.divider()

        sections = {

            "Urgency Signals":
            social["urgency_detected"],

            "Fear Signals":
            social["fear_detected"],

            "Authority Impersonation":
            social["authority_detected"],

            "Financial Bait":
            social["financial_bait_detected"],

            "Credential Requests":
            social["credential_requests"]
        }

        for title, values in sections.items():

            st.markdown(f"### {title}")

            if values:

                for item in values:

                    st.warning(item)

            else:

                st.success(
                    "No indicators detected"
                )

    # =====================================================
    # AI REASONING TAB
    # =====================================================

    with tab5:

        st.markdown(
            "## 🤖 AI Threat Reasoning"
        )

        llm = result[
            "llm_analysis"
        ]

        st.metric(
            "LLM Confidence",
            f"{llm['confidence']}%"
        )

        st.write(
            f"**Threat Level:** {llm['threat_level']}"
        )

        st.divider()

        st.markdown(
            "### Threat Reasoning"
        )

        st.write(
            llm["reasoning"]
        )

        st.divider()

        st.markdown(
            "### Recommended Action"
        )

        st.info(
            llm["recommended_action"]
        )

    # =====================================================
    # RAW JSON TAB
    # =====================================================

    # with tab6:

    #     st.markdown(
    #         "## 📄 Structured JSON Output"
    #     )

    #     st.json(result)

    #     json_report = json.dumps(
    #         result,
    #         indent=2
    #     )

    #     st.download_button(

    #         label="⬇️ Download JSON Report",

    #         data=json_report,

    #         file_name="phishing_report.json",

    #         mime="application/json"
    #     )