"""
backend/services/threat_service.py
Query helpers for threats, filtering, sorting, IOC search.
"""
from backend.db import get_connection


def query_threats(severity=None, category=None, status=None,
                  indicator_type=None, min_risk=None, min_conf=None,
                  sort="newest", limit=500):
    conn = get_connection()
    cur = conn.cursor()
    sql = ["SELECT t.*, i.indicator_type, i.indicator_value FROM threats t "
           "LEFT JOIN indicators i ON t.threat_id = i.threat_id WHERE 1=1"]
    params = []
    if severity:
        sql.append("AND t.severity = ?")
        params.append(severity)
    if category:
        sql.append("AND t.category = ?")
        params.append(category)
    if status:
        sql.append("AND t.status = ?")
        params.append(status)
    if indicator_type:
        sql.append("AND i.indicator_type = ?")
        params.append(indicator_type)
    if min_risk is not None:
        sql.append("AND t.risk_score >= ?")
        params.append(float(min_risk))
    if min_conf is not None:
        sql.append("AND t.confidence_score >= ?")
        params.append(int(min_conf))

    if sort == "risk":
        sql.append("ORDER BY t.risk_score DESC")
    elif sort == "confidence":
        sql.append("ORDER BY t.confidence_score DESC")
    elif sort == "oldest":
        sql.append("ORDER BY t.first_seen ASC")
    else:
        sql.append("ORDER BY t.first_seen DESC")

    sql.append("LIMIT ?")
    params.append(limit)

    cur.execute(" ".join(sql), params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_threat(threat_id: str) -> dict | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,))
    t = cur.fetchone()
    if not t:
        conn.close()
        return None
    t = dict(t)
    cur.execute("SELECT * FROM indicators WHERE threat_id = ?", (threat_id,))
    t["indicators"] = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM attack_mappings WHERE threat_id = ?", (threat_id,))
    t["attack_mappings"] = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM alerts WHERE threat_id = ?", (threat_id,))
    t["alerts"] = [dict(r) for r in cur.fetchall()]
    cur.execute(
        "SELECT * FROM analyst_notes WHERE threat_id = ? ORDER BY created_at DESC",
        (threat_id,),
    )
    t["notes"] = [dict(r) for r in cur.fetchall()]
    conn.close()
    return t


def search_indicator(value: str) -> dict:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM indicators WHERE indicator_value = ? LIMIT 1", (value,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"found": False, "indicator_value": value}
    threat_id = row["threat_id"]
    cur.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,))
    t = dict(cur.fetchone())
    conn.close()
    return {
        "found": True,
        "indicator_type": row["indicator_type"],
        "indicator_value": row["indicator_value"],
        "threat_id": threat_id,
        "category": t["category"],
        "risk_score": t["risk_score"],
        "severity": t["severity"],
        "confidence_score": t["confidence_score"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "status": t["status"],
    }


def add_note(threat_id: str, note: str):
    from datetime import datetime
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO analyst_notes (threat_id, note, created_at) VALUES (?,?,?)",
        (threat_id, note, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    conn.close()