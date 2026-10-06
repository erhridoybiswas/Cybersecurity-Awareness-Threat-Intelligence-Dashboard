from flask import Blueprint, jsonify
from backend.db import get_connection

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.get("/stats")
def stats():
    conn = get_connection()
    cur = conn.cursor()
    def one(q, p=()):
        cur.execute(q, p)
        return cur.fetchone()[0]

    data = {
        "total_threats": one("SELECT COUNT(*) FROM threats"),
        "critical": one("SELECT COUNT(*) FROM threats WHERE severity='CRITICAL'"),
        "high": one("SELECT COUNT(*) FROM threats WHERE severity='HIGH'"),
        "active_indicators": one("SELECT COUNT(*) FROM indicators"),
        "open_investigations": one(
            "SELECT COUNT(*) FROM alerts WHERE status IN ('NEW','INVESTIGATING')"),
        "avg_confidence": round(one(
            "SELECT AVG(confidence_score) FROM threats") or 0, 2),
        "vulnerabilities_tracked": one("SELECT COUNT(*) FROM vulnerabilities"),
    }
    conn.close()
    return jsonify(data)


@dashboard_bp.get("/trends")
def trends():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT severity, COUNT(*) c FROM threats GROUP BY severity")
    by_sev = {r[0]: r[1] for r in cur.fetchall()}
    cur.execute("SELECT category, COUNT(*) c FROM threats GROUP BY category")
    by_cat = {r[0]: r[1] for r in cur.fetchall()}
    cur.execute("SELECT indicator_type, COUNT(*) c FROM indicators GROUP BY indicator_type")
    by_ind = {r[0]: r[1] for r in cur.fetchall()}
    cur.execute("SELECT status, COUNT(*) c FROM threats GROUP BY status")
    by_status = {r[0]: r[1] for r in cur.fetchall()}
    cur.execute("SELECT mitre_tactic, COUNT(*) c FROM attack_mappings GROUP BY mitre_tactic")
    by_tac = {r[0]: r[1] for r in cur.fetchall() if r[0]}
    cur.execute("SELECT substr(first_seen,1,10) d, COUNT(*) c FROM threats GROUP BY d ORDER BY d")
    by_day = [{"date": r[0], "count": r[1]} for r in cur.fetchall()]
    cur.execute("SELECT severity, COUNT(*) c FROM vulnerabilities GROUP BY severity")
    by_vuln = {r[0]: r[1] for r in cur.fetchall()}
    conn.close()
    return jsonify({
        "by_severity": by_sev,
        "by_category": by_cat,
        "by_indicator_type": by_ind,
        "by_status": by_status,
        "by_tactic": by_tac,
        "by_day": by_day,
        "vulnerabilities_by_severity": by_vuln,
    })


@dashboard_bp.get("/executive")
def executive():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT category, COUNT(*) c FROM threats GROUP BY category "
                "ORDER BY c DESC LIMIT 5")
    top_cat = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]
    cur.execute("SELECT product_category, COUNT(*) c FROM vulnerabilities "
                "GROUP BY product_category ORDER BY c DESC LIMIT 5")
    top_vuln = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]
    cur.execute("SELECT COUNT(*) FROM threats WHERE severity IN ('HIGH','CRITICAL')")
    high_plus = cur.fetchone()[0]
    conn.close()
    return jsonify({
        "headline": "Defensive posture summary from synthetic data.",
        "high_or_critical_threats": high_plus,
        "top_threat_categories": top_cat,
        "top_vulnerability_categories": top_vuln,
        "recommended_priorities": [
            "Reinforce phishing awareness training",
            "Patch internet-facing assets first",
            "Review MFA coverage on critical accounts",
            "Validate backups for ransomware resilience",
        ],
    })