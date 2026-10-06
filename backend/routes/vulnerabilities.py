from flask import Blueprint, jsonify, request
from backend.db import get_connection

vulns_bp = Blueprint("vulnerabilities", __name__, url_prefix="/api/vulnerabilities")


def calculate_vulnerability_priority(cvss, asset_criticality,
                                      exposure, exploitation, business_context):
    """
    Contextual vulnerability prioritization:
      CVSS * asset criticality * exposure * exploitation * business context
    Returns score 0-100.
    """
    ac_map = {"LOW": 0.6, "MEDIUM": 0.8, "HIGH": 1.0, "CRITICAL": 1.2}
    ex_map = {"INTERNAL": 0.7, "PARTNER": 0.9, "INTERNET": 1.2}
    exploit_map = {"NO_KNOWN": 0.7, "THEORETICAL": 0.9, "OBSERVED_IN_WILD": 1.3}
    bc_map = {"LOW": 0.8, "MEDIUM": 1.0, "HIGH": 1.2}

    score = (
        (cvss / 10.0) * 50
        * ac_map.get(asset_criticality, 1.0)
        * ex_map.get(exposure, 1.0)
        * exploit_map.get(exploitation, 1.0)
        * bc_map.get(business_context, 1.0)
    )
    # Normalize roughly to 0-100
    return round(min(100.0, score * 1.0), 2)


@vulns_bp.get("")
def list_vulns():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vulnerabilities ORDER BY cvss_score DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@vulns_bp.post("/<cve_id>/priority")
def priority(cve_id):
    data = request.get_json(silent=True) or {}
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
    v = cur.fetchone()
    if not v:
        conn.close()
        return jsonify({"error": "not found"}), 404
    score = calculate_vulnerability_priority(
        v["cvss_score"],
        data.get("asset_criticality", "MEDIUM"),
        data.get("exposure", "INTERNAL"),
        v["exploitation_status"] or "NO_KNOWN",
        data.get("business_context", "MEDIUM"),
    )
    cur.execute("UPDATE vulnerabilities SET priority_score = ? WHERE cve_id = ?",
                (score, cve_id))
    conn.commit()
    conn.close()
    return jsonify({"cve_id": cve_id, "priority_score": score,
                    "note": "CVSS alone is not enough for prioritization."})