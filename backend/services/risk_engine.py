"""
backend/services/risk_engine.py
Risk scoring and severity classification.
"""
SEVERITY_SCORE = {
    "INFORMATIONAL": 10,
    "LOW": 30,
    "MEDIUM": 55,
    "HIGH": 75,
    "CRITICAL": 95,
}
RELIABILITY_WEIGHT = {"A": 1.0, "B": 0.85, "C": 0.65, "D": 0.40}


def classify_risk(score: float) -> str:
    if score <= 20:
        return "INFORMATIONAL"
    if score <= 40:
        return "LOW"
    if score <= 60:
        return "MEDIUM"
    if score <= 80:
        return "HIGH"
    return "CRITICAL"


def calculate_threat_risk(severity: str,
                          confidence: int,
                          recency_days: int,
                          observations: int,
                          source_reliability: str,
                          related_alerts: int = 0) -> dict:
    """
    Weighted risk score (0-100).

    Weights:
      Severity              30%
      Confidence            25%
      Recency               15%
      Observations          10%
      Source reliability    10%
      Related alerts/ctx    10%
    """
    sev = SEVERITY_SCORE.get(severity, 50)
    conf = max(0, min(100, confidence))
    recency = max(0, 100 - recency_days * 2)
    obs = min(100, observations * 5)
    rel = RELIABILITY_WEIGHT.get(source_reliability, 0.5) * 100
    ctx = min(100, related_alerts * 20)

    risk = (
        0.30 * sev
        + 0.25 * conf
        + 0.15 * recency
        + 0.10 * obs
        + 0.10 * rel
        + 0.10 * ctx
    )
    risk = round(max(0.0, min(100.0, risk)), 2)
    return {
        "risk_score": risk,
        "classification": classify_risk(risk),
        "components": {
            "severity": sev,
            "confidence": conf,
            "recency": recency,
            "observations": obs,
            "source_reliability": rel,
            "context": ctx,
        },
        "note": "High risk does NOT mean confirmed compromise.",
    }