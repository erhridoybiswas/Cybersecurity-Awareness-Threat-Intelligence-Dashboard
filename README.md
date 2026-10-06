# Cybersecurity Awareness & Threat Intelligence Dashboard

A **defensive** cybersecurity project combining SOC-style threat intelligence,
IOC analysis, risk & confidence scoring, MITRE ATT&CK mapping, vulnerability
awareness, and an interactive security awareness training module.

> **Disclaimer**
> This project is designed exclusively for defensive cybersecurity education,
> threat-intelligence analysis, and security awareness. It does not execute,
> deploy, or interact with malicious payloads or unauthorized systems.
> All data is **synthetic and safe**.

## Overview
- **Synthetic threat intelligence dataset** (2,000+ records, RFC-5737 IPs,
  example.com domains, synthetic hashes, synthetic CVEs).
- **SOC dashboard** with charts, filters, IOC search, and investigation view.
- **Risk + confidence scoring** with clear separation of both concepts.
- **MITRE ATT&CK** high-level mapping.
- **Vulnerability awareness** with contextual prioritization.
- **Awareness Center** (15 modules) + **30-question quiz** with personalized
  learning recommendations.
- **Executive summary** for non-technical stakeholders.

## Problem Statement
Most students learn cybersecurity concepts in isolation. This project shows
how threat intelligence, IOC analysis, risk scoring, and human awareness fit
together inside a real SOC workflow.

## Features
- Threat feed with 10 categories and 6 indicator types
- IOC validation engine (`validate_indicator`)
- IOC enrichment (local, synthetic)
- Weighted risk + confidence scoring
- Source reliability (A/B/C/D)
- Threat correlation (clusters) and alert correlation (anti alert-fatigue)
- MITRE ATT&CK mapping and visualization
- Vulnerability awareness with contextual prioritization
- Awareness Center (phishing, passwords, MFA, ransomware, etc.)
- 30-question quiz with awareness score & recommendations
- Executive cybersecurity summary

## Architecture
Synthetic Data → Ingestion → Normalization → IOC Validation
→ Enrichment → Risk + Confidence → Correlation → Alerts
→ ATT&CK Mapping → SQLite → REST API → SOC Dashboard → Analyst
↘ Awareness Center → Quiz → Recommendations

## Technology Stack
- **Backend**: Python 3.11+, Flask, Flask-CORS
- **DB**: SQLite
- **Analytics**: Pandas (used in generator)
- **Charts**: Chart.js
- **Tests**: pytest

## Installation
```bash
git clone https://github.com/<you>/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
pip install -r requirements.txt
# 1) Generate synthetic data
python data/generate_threat_data.py

# 2) Initialize + seed DB & run backend
python -m backend.app
Open http://127.0.0.1:5000/

Try searching for: 198.51.100.25, example.com, CVE-2026-12345.

API Documentation
Method	Endpoint	Purpose
GET	/api/health	Health check
GET	/api/threats	List + filter + sort
GET	/api/threats/{id}	Threat detail
POST	/api/threats/{id}/notes	Analyst note
GET	/api/indicators/validate?value=	Syntactic validation
GET	/api/indicators/search?value=	Lookup + enrichment
GET	/api/alerts	Alerts list
PUT	/api/alerts/{id}/status	Update alert status
GET	/api/dashboard/stats	Top card numbers
GET	/api/dashboard/trends	Chart data
GET	/api/dashboard/executive	Executive summary
GET	/api/vulnerabilities	Vulnerability list
POST	/api/vulnerabilities/{cve}/priority	Contextual priority
GET	/api/awareness/modules	Awareness modules
GET	/api/quiz	Quiz questions
POST	/api/quiz/submit	Score + recommendations
Testing
bash
pytest -v
35 automated tests.

Security & Privacy
Never auto-visit suspicious URLs / IPs.

Validate API input; sanitize outputs (XSS safe rendering).

Rate limit + RBAC recommended for production.

Use HTTPS and environment variables for secrets.

Threat-intel data itself requires access controls.

Limitations
Synthetic data only; no live feeds.

ATT&CK mapping is high-level and category-based.

No real attribution or live telemetry.

Indicators can become stale — IOC ≠ confirmed compromise.

Future Improvements
STIX/TAXII, SIEM/SOAR integrations, CISA KEV awareness, EPSS-style
prioritization, ATT&CK Navigator export, Docker, CI/CD, RBAC.

Learning Outcomes
Understanding threat intelligence lifecycle

IOC validation / enrichment / scoring

Risk vs Confidence distinction

SOC workflow & alert triage

Human-layer security awareness

Ethical Disclaimer
This project is designed exclusively for defensive cybersecurity education,
threat-intelligence analysis, and security awareness. It does not execute,
deploy, or interact with malicious payloads or unauthorized systems.

Author
HRIDOY BISWAS