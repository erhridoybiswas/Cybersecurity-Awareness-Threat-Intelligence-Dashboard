"""
backend/services/enrichment_engine.py
Local synthetic enrichment (no external API, no network calls).
"""
from backend.db import get_connection


def enrich_indicator(indicator_value: str) -> dict:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM indicators WHERE indicator_value = ? LIMIT 1",
        (indicator_value,),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return {
            "found": False,
            "indicator_value": indicator_value,
            "notes": "Not present in synthetic dataset.",
        }
    threat_id = row["threat_id"]
    cur.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,))
    threat = cur.fetchone()
    cur.execute(
        "SELECT indicator_type, indicator_value FROM indicators WHERE threat_id = ?",
        (threat_id,),
    )
    related = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT COUNT(*) AS c FROM alerts WHERE threat_id = ?", (threat_id,))
    related_alerts = cur.fetchone()["c"]
    conn.close()

    return {
        "found": True,
        "indicator_type": row["indicator_type"],
        "indicator_value": row["indicator_value"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "threat_id": threat_id,
        "threat_name": threat["threat_name"],
        "category": threat["category"],
        "severity": threat["severity"],
        "risk_score": threat["risk_score"],
        "confidence_score": threat["confidence_score"],
        "source_name": threat["source_name"],
        "source_reliability": threat["source_reliability"],
        "mitre_tactic": threat["mitre_tactic"],
        "mitre_technique": threat["mitre_technique"],
        "mitre_technique_id": threat["mitre_technique_id"],
        "cve_id": threat["cve_id"],
        "related_indicators": related,
        "related_alerts": related_alerts,
        "analyst_notes": (
            "Synthetic enrichment only. Never auto-connect to indicators."
        ),
    }