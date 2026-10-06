"""
backend/services/attack_mapper.py
Defensive MITRE ATT&CK helpers (no exploitation guidance).
"""

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]


def list_tactics():
    return TACTIC_ORDER


def map_category_to_tactics(category: str) -> list:
    """Safe high-level mapping, only when justified by category."""
    mapping = {
        "PHISHING": ["Initial Access"],
        "CREDENTIAL_THREATS": ["Credential Access", "Defense Evasion"],
        "RANSOMWARE": ["Impact"],
        "MALWARE": ["Execution", "Persistence"],
        "WEB_THREATS": ["Initial Access"],
        "NETWORK_THREATS": ["Command and Control"],
        "VULNERABILITY_EXPOSURE": ["Initial Access"],
        "SOCIAL_ENGINEERING": ["Reconnaissance"],
        "DATA_EXPOSURE": ["Exfiltration"],
        "ACCOUNT_SECURITY": ["Persistence", "Credential Access"],
    }
    return mapping.get(category, [])