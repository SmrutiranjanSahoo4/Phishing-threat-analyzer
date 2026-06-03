# AI Phishing Threat Analyzer

An explainable AI-powered phishing detection and threat intelligence system built with Python, Streamlit, and LLM-assisted security reasoning.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Usage](#usage)
- [Detection Techniques](#detection-techniques)
- [Future Improvements](#future-improvements)
- [Educational Purpose](#educational-purpose)
- [Skills Demonstrated](#skills-demonstrated)

## Features

- **URL Threat Analysis** — Detects suspicious TLDs, typosquatting/brand impersonation, IP-based URLs, URL shorteners, excessive subdomains, phishing keywords, and overly long URLs.
- **Sender Analysis** — Detects brand impersonation, suspicious email patterns, free-email abuse, random-character senders, and spoofing indicators.
- **Social Engineering Detection** — Flags urgency manipulation, fear/authority tactics, financial bait, credential-harvesting language, excessive capitalization, and punctuation.
- **AI Threat Reasoning** — Uses a local or hosted LLM (example: Mistral) to produce threat assessments, explainable reasoning, identified attack techniques, and recommended mitigation steps.
- **Threat Aggregation Engine** — Normalizes and combines signals into a final verdict, risk score, and confidence estimate.
- **Interactive Dashboard** — Streamlit UI with multi-tab analysis, visualizations, and explainable reports.

## Architecture

Input flows through separate analysis modules and into an LLM reasoning engine; results are then aggregated for presentation.

```
Input Message
   ├─ URL Analysis
   ├─ Sender Analysis
   └─ Social Analysis
      └─> LLM Threat Reasoning Engine
          └─> Threat Aggregation Engine
              └─> Final Threat Dashboard
```

## Project Structure

```
project/
├── aggregate.py      # Threat aggregation engine
├── llm.py            # LLM reasoning module
├── main.py           # Main detection pipeline
├── sender.py         # Sender spoofing analysis
├── social.py         # Social engineering detection
├── url.py            # URL intelligence analysis
├── ui.py             # Streamlit dashboard UI
├── requirements.txt  # Python dependencies
└── README.md         # Project README
```

## Installation

1. Clone the repository

```bash
git clone https://github.com/yourusername/ai-phishing-analyzer.git
cd ai-phishing-analyzer
```

2. Create and activate a virtual environment

```bash
python -m venv venv
source venv/bin/activate
```

3. Install dependencies

```bash
pip install -r requirements.txt
```

### Recommended packages

- streamlit
- mistralai (or another LLM client)
- python-dotenv
- python-whois

## Environment Variables

Create a `.env` file in the project root with the following variables:

```
MISTRAL_API_KEY=your_api_key_here
```

## Usage

Run the Streamlit dashboard:

```bash
streamlit run ui.py
```

Or run the main pipeline (example):

```bash
python main.py --input "http://example.com" 
```

## Detection Techniques

| Module             | Techniques                                  |
| ------------------ | ------------------------------------------- |
| URL Analysis       | Typosquatting, TLD analysis, URL heuristics |
| Sender Analysis    | Spoofing detection, impersonation           |
| Social Engineering | Psychological-manipulation detection        |
| Domain Analysis    | WHOIS / domain-age intelligence             |
| LLM Analysis       | Explainable phishing reasoning              |
| Aggregation Engine | Risk normalization and scoring              |

## Future Improvements

- SPF/DKIM/DMARC analysis
- Threat-intel API integration
- Reputation scoring and third-party feeds
- Real-time email scanning
- Phishing dataset benchmarking
- ML-based phishing classifier
- Browser extension integration
- Async threat scanning and queueing
- Logging, monitoring, and analytics
- REST API backend

## Educational Purpose

This project is intended for defensive security research, education, and threat-analysis practice only.

## Skills Demonstrated

- Python development
- Cybersecurity fundamentals
- Threat intelligence concepts
- LLM integration and prompt engineering
- Streamlit dashboard development
- Explainable AI systems
- Modular software architecture

---

If you'd like, I can also:

- add badges (license, Python version, CI)
- generate a requirements subset from your virtualenv
- add CONTRIBUTING and LICENSE files

Tell me which you'd like next.