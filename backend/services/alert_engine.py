"""
backend/services/alert_engine.py
Alert creation with thresholds and simple deduplication.
"""
from datetime import datetime

from backend.db import get_connection

RISK_THRESHOLD = 65
CONFIDENCE_THRESHOLD = 60


def generate_threat_alert(threat: dict) -> dict | None:
    """Return alert dict if thresholds are crossed, else None."""
    risk = threat.get("risk_score", 0)
    conf = threat.get("confidence_score", 0)
    if risk < RISK_THRESHOLD or conf < CONFIDENCE_THRESHOLD:
        return None

    alert_type = "RISK_THRESHOLD_EXCEEDED"
    if threat.get("mitre_tactic") and threat["mitre_tactic"] != "N/A":
        alert_type = f"ATTACK_MAPPED_{threat['mitre_tactic'].upper().replace(' ', '_')}"

    return {
        "threat_id": threat["threat_id"],
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "alert_type": alert_type,
        "severity": threat["severity"],
        "risk_score": risk,
        "confidence_score": conf,
        "description": (
            f"[SYNTHETIC] Alert for {threat['threat_id']} "
            f"({threat['category']}). Review in SOC workflow."
        ),
        "status": "NEW",
        "observation_count": 1,
    }


def persist_alerts_from_threats():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM threats")
    threats = [dict(r) for r in cur.fetchall()]

    created = 0
    for t in threats:
        a = generate_threat_alert(t)
        if not a:
            continue
        cur.execute(
            """SELECT COUNT(*) AS c FROM alerts
               WHERE threat_id = ? AND alert_type = ?""",
            (a["threat_id"], a["alert_type"]),
        )
        if cur.fetchone()["c"] > 0:
            continue
        cur.execute(
            """INSERT INTO alerts
               (threat_id, timestamp, alert_type, severity, risk_score,
                confidence_score, description, status, observation_count)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                a["threat_id"], a["timestamp"], a["alert_type"], a["severity"],
                a["risk_score"], a["confidence_score"], a["description"],
                a["status"], a["observation_count"],
            ),
        )
        created += 1
    conn.commit()
    conn.close()
    print(f"[+] Created {created} alerts.")