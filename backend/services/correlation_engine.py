"""
backend/services/correlation_engine.py
Groups threats by category + time window into clusters.
"""
from collections import defaultdict
from datetime import datetime, timedelta

from backend.db import get_connection


def correlate_threats(window_hours: int = 24) -> list:
    """
    Group threats that share category AND fall within window_hours.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM threats ORDER BY first_seen ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    clusters = defaultdict(list)
    for r in rows:
        try:
            ts = datetime.strptime(r["first_seen"], "%Y-%m-%d %H:%M:%S")
        except Exception:
            continue
        bucket = ts.replace(minute=0, second=0) - timedelta(
            hours=ts.hour % window_hours
        )
        key = f"{r['category']}_{bucket.strftime('%Y%m%d%H')}"
        clusters[key].append(r)

    output = []
    for key, items in clusters.items():
        if len(items) < 2:
            continue
        output.append({
            "cluster_id": key,
            "category": items[0]["category"],
            "member_count": len(items),
            "members": [
                {"threat_id": i["threat_id"],
                 "indicator_value": i["indicator_value"] if "indicator_value" in i else None,
                 "threat_name": i["threat_name"],
                 "severity": i["severity"]}
                for i in items[:25]
            ],
            "note": "Correlation indicates relationship, not attribution.",
        })
    output.sort(key=lambda c: c["member_count"], reverse=True)
    return output[:25]


def correlate_alerts(min_count: int = 2) -> list:
    """Group identical alerts to prevent analyst alert fatigue."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT threat_id, alert_type, severity,
                  COUNT(*) as occurrences,
                  SUM(observation_count) as total_obs,
                  MAX(risk_score) as max_risk,
                  MAX(timestamp) as last_seen
           FROM alerts
           GROUP BY threat_id, alert_type, severity
           HAVING COUNT(*) >= ?
           ORDER BY occurrences DESC""",
        (min_count,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows