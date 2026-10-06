"""
data/generate_threat_data.py
--------------------------------------------------------------------------------
Generates a fully SYNTHETIC threat intelligence dataset for the
Cybersecurity Awareness & Threat Intelligence Dashboard.

ALL indicators are reserved / documentation-safe:
  - IPs       : RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
  - Domains   : example.com / example.org / example.net / *.invalid
  - URLs      : only documentation domains
  - Hashes    : randomly generated (no real malware hashes)
  - CVEs      : clearly synthetic (future year + high IDs)

This file is for defensive education only.
"""

import csv
import os
import random
from datetime import datetime, timedelta

random.seed(42)

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
THREAT_CSV = os.path.join(OUT_DIR, "threat_intelligence_dataset.csv")
VULN_CSV = os.path.join(OUT_DIR, "vulnerabilities.csv")

CATEGORIES = [
    "PHISHING", "MALWARE", "RANSOMWARE", "CREDENTIAL_THREATS",
    "WEB_THREATS", "NETWORK_THREATS", "VULNERABILITY_EXPOSURE",
    "SOCIAL_ENGINEERING", "DATA_EXPOSURE", "ACCOUNT_SECURITY",
]

INDICATOR_TYPES = [
    "IP_ADDRESS", "DOMAIN", "URL", "FILE_HASH",
    "EMAIL_SENDER_DOMAIN", "CVE_ID",
]

SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_WEIGHTS = [0.10, 0.22, 0.30, 0.25, 0.13]

STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]
STATUS_WEIGHTS = [0.30, 0.20, 0.28, 0.15, 0.07]

SOURCES = [
    ("Internal SOC", "A"),
    ("Security Vendor", "B"),
    ("Public Threat Feed", "C"),
    ("Research Report", "B"),
    ("Community Submission", "D"),
    ("Unknown Source", "D"),
]

MITRE_MAP = {
    "PHISHING": [
        ("Initial Access", "Phishing", "T1566"),
        ("Initial Access", "Spearphishing Link", "T1566.002"),
    ],
    "CREDENTIAL_THREATS": [
        ("Credential Access", "Brute Force", "T1110"),
        ("Defense Evasion", "Valid Accounts", "T1078"),
    ],
    "RANSOMWARE": [
        ("Impact", "Data Encrypted for Impact", "T1486"),
    ],
    "MALWARE": [
        ("Execution", "Command and Scripting Interpreter", "T1059"),
        ("Persistence", "Account Manipulation", "T1098"),
    ],
    "WEB_THREATS": [
        ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    ],
    "NETWORK_THREATS": [
        ("Command and Control", "Application Layer Protocol", "T1071"),
    ],
    "VULNERABILITY_EXPOSURE": [
        ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    ],
    "SOCIAL_ENGINEERING": [
        ("Reconnaissance", "Phishing for Information", "T1598"),
    ],
    "DATA_EXPOSURE": [
        ("Exfiltration", "Exfiltration Over C2 Channel", "T1041"),
    ],
    "ACCOUNT_SECURITY": [
        ("Persistence", "Account Manipulation", "T1098"),
        ("Credential Access", "Brute Force", "T1110"),
    ],
}


def random_ip():
    """Return an RFC-5737 documentation IP address."""
    prefix = random.choice(["192.0.2", "198.51.100", "203.0.113"])
    return f"{prefix}.{random.randint(1, 254)}"


def random_domain():
    base = random.choice(["example.com", "example.org", "example.net"])
    sub = random.choice(["login", "secure", "verify", "mail", "auth",
                         "portal", "update", "account"])
    return f"{sub}.{base}" if random.random() < 0.5 else base


def random_invalid_domain():
    return f"demo-{random.randint(1000, 9999)}.invalid"


def random_url():
    d = random_domain()
    path = random.choice(["/login", "/verify", "/account/update",
                          "/secure/signin", "/docs", "/help"])
    return f"https://{d}{path}"


def random_email_domain():
    base = random.choice(["example.com", "example.org", "example.net"])
    sub = random.choice(["mail", "smtp", "sender", "noreply"])
    return f"{sub}.{base}"


def random_hash(kind="sha256"):
    hexdigits = "0123456789abcdef"
    length = {"md5": 32, "sha1": 40, "sha256": 64}[kind]
    return "".join(random.choice(hexdigits) for _ in range(length))


def random_cve():
    """Clearly synthetic CVE ID (future year + high number)."""
    return f"CVE-2026-{random.randint(10000, 99999)}"


def make_indicator(indicator_type):
    if indicator_type == "IP_ADDRESS":
        return random_ip()
    if indicator_type == "DOMAIN":
        return random_domain() if random.random() < 0.7 else random_invalid_domain()
    if indicator_type == "URL":
        return random_url()
    if indicator_type == "FILE_HASH":
        return random_hash(random.choice(["md5", "sha1", "sha256"]))
    if indicator_type == "EMAIL_SENDER_DOMAIN":
        return random_email_domain()
    if indicator_type == "CVE_ID":
        return random_cve()
    return "example.com"


def generate_threats(n=2000):
    rows = []
    base_time = datetime(2026, 1, 1, 0, 0, 0)
    for i in range(1, n + 1):
        tid = f"THR-2026-{i:04d}"
        category = random.choices(CATEGORIES, k=1)[0]
        indicator_type = random.choices(
            INDICATOR_TYPES,
            weights=[0.22, 0.22, 0.18, 0.18, 0.10, 0.10],
            k=1,
        )[0]
        indicator_value = make_indicator(indicator_type)
        source_name, reliability = random.choice(SOURCES)
        severity = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0]
        confidence = random.randint(30, 98)
        risk_score = round(
            0.45 * {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 55,
                    "HIGH": 75, "CRITICAL": 95}[severity]
            + 0.35 * confidence
            + 0.20 * random.randint(40, 100),
            2,
        )
        risk_score = max(0, min(100, risk_score))
        status = random.choices(STATUSES, weights=STATUS_WEIGHTS, k=1)[0]
        first_seen = base_time + timedelta(
            days=random.randint(0, 90),
            hours=random.randint(0, 23),
        )
        last_seen = first_seen + timedelta(
            days=random.randint(0, 20),
            hours=random.randint(0, 23),
        )
        region = random.choice(["EU", "US", "APAC", "Unknown", "Global"])
        description = (
            f"Synthetic {category.lower().replace('_', ' ')} observation "
            f"recorded from {source_name}. Demo data only."
        )
        tactic, technique, technique_id = "N/A", "N/A", "N/A"
        if category in MITRE_MAP and random.random() < 0.6:
            tactic, technique, technique_id = random.choice(MITRE_MAP[category])
        cve_id = random_cve() if indicator_type == "CVE_ID" else ""

        rows.append({
            "threat_id": tid,
            "timestamp": first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "threat_name": f"Synthetic {category.title()} Event {i}",
            "threat_category": category,
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "source_name": source_name,
            "source_reliability": reliability,
            "confidence_score": confidence,
            "severity": severity,
            "risk_score": risk_score,
            "status": status,
            "first_seen": first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": last_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "country_or_region_optional": region,
            "description": description,
            "mitre_tactic_optional": tactic,
            "mitre_technique_optional": technique,
            "mitre_technique_id_optional": technique_id,
            "cve_id_optional": cve_id,
        })
    return rows


def write_threats(rows, path=THREAT_CSV):
    fields = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] Wrote {len(rows)} synthetic threat records -> {path}")


def generate_vulnerabilities(n=120):
    rows = []
    for i in range(1, n + 1):
        cvss = round(random.uniform(2.0, 10.0), 1)
        if cvss >= 9.0:
            severity = "CRITICAL"
        elif cvss >= 7.0:
            severity = "HIGH"
        elif cvss >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        rows.append({
            "cve_id": f"CVE-2026-{10000 + i}",
            "product_category": random.choice(
                ["Web Server", "Email Gateway", "VPN Appliance",
                 "Operating System", "Database", "Container Runtime"]
            ),
            "severity": severity,
            "cvss_score": cvss,
            "published_date": (
                datetime(2026, 1, 1) + timedelta(days=random.randint(0, 200))
            ).strftime("%Y-%m-%d"),
            "patch_available": random.choice(["YES", "NO"]),
            "exploitation_status_demo": random.choice(
                ["NO_KNOWN", "THEORETICAL", "OBSERVED_IN_WILD"]
            ),
            "description": (
                "SYNTHETIC vulnerability record for defensive awareness only. "
                "Not a real CVE."
            ),
        })
    return rows


def write_vulnerabilities(rows, path=VULN_CSV):
    fields = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] Wrote {len(rows)} synthetic vulnerabilities -> {path}")


if __name__ == "__main__":
    threats = generate_threats(2000)
    write_threats(threats)
    write_vulnerabilities(generate_vulnerabilities(120))
    print("[+] Synthetic dataset generation complete.")
    print("    SYNTHETIC / DEMO ONLY - do not treat as real intelligence.")