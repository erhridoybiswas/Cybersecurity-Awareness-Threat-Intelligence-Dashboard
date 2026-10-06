from flask import Blueprint, jsonify, request
from backend.db import get_connection

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


@alerts_bp.get("")
def list_alerts():
    status = request.args.get("status")
    conn = get_connection()
    cur = conn.cursor()
    if status:
        cur.execute("SELECT * FROM alerts WHERE status = ? ORDER BY timestamp DESC",
                    (status,))
    else:
        cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 500")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@alerts_bp.put("/<int:alert_id>/status")
def update_status(alert_id):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in {"NEW", "INVESTIGATING", "MONITORING",
                      "RESOLVED", "FALSE_POSITIVE"}:
        return jsonify({"error": "invalid status"}), 400
    conn = get_connection()
    conn.execute("UPDATE alerts SET status = ? WHERE alert_id = ?",
                 (status, alert_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})