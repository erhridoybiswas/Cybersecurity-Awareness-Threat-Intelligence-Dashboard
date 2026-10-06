"""
backend/services/ioc_validator.py

Syntactic indicator validation.

IMPORTANT: Validation only answers 'Is this the right FORMAT?'
It does NOT answer 'Is this malicious?'
"""
import ipaddress
import re

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)
URL_RE = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
EMAIL_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.[A-Za-z0-9-]{1,63})+$"
)


def _try_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return ("IP_ADDRESS", str(ip),
                f"Valid IPv{ip.version} address")
    except ValueError:
        return None


def validate_indicator(value: str) -> dict:
    """Return syntactic validation for a given indicator string."""
    result = {
        "valid": False,
        "indicator_type": None,
        "normalized_value": None,
        "validation_notes": [],
    }
    if not value or not isinstance(value, str):
        result["validation_notes"].append("Empty or non-string input.")
        return result

    v = value.strip()

    ip = _try_ip(v)
    if ip:
        result.update(valid=True, indicator_type=ip[0],
                      normalized_value=ip[1])
        result["validation_notes"].append(ip[2])
        return result

    if CVE_RE.match(v):
        result.update(valid=True, indicator_type="CVE_ID",
                      normalized_value=v.upper())
        result["validation_notes"].append("Matches CVE ID format.")
        return result

    if MD5_RE.match(v):
        result.update(valid=True, indicator_type="FILE_HASH",
                      normalized_value=v.lower())
        result["validation_notes"].append("Matches MD5 hex format (32 chars).")
        return result

    if SHA1_RE.match(v):
        result.update(valid=True, indicator_type="FILE_HASH",
                      normalized_value=v.lower())
        result["validation_notes"].append("Matches SHA-1 hex format (40 chars).")
        return result

    if SHA256_RE.match(v):
        result.update(valid=True, indicator_type="FILE_HASH",
                      normalized_value=v.lower())
        result["validation_notes"].append("Matches SHA-256 hex format (64 chars).")
        return result

    if URL_RE.match(v):
        result.update(valid=True, indicator_type="URL",
                      normalized_value=v)
        result["validation_notes"].append("Matches basic HTTP/HTTPS URL format.")
        return result

    if DOMAIN_RE.match(v):
        result.update(valid=True, indicator_type="DOMAIN",
                      normalized_value=v.lower())
        result["validation_notes"].append("Matches domain format.")
        return result

    if EMAIL_DOMAIN_RE.match(v):
        result.update(valid=True, indicator_type="EMAIL_SENDER_DOMAIN",
                      normalized_value=v.lower())
        result["validation_notes"].append("Matches email sender domain format.")
        return result

    result["validation_notes"].append("No known indicator format matched.")
    return result