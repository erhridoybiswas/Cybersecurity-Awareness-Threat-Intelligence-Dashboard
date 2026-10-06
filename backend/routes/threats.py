from flask import Blueprint, jsonify, request

from backend.services.threat_service import (
    query_threats, get_threat, add_note,
)

threats_bp = Blueprint("threats", __name__, url_prefix="/api/threats")


@threats_bp.get("")
def list_threats():
    return jsonify(query_threats(
        severity=request.args.get("severity"),
        category=request.args.get("category"),
        status=request.args.get("status"),
        indicator_type=request.args.get("indicator_type"),
        min_risk=request.args.get("min_risk"),
        min_conf=request.args.get("min_confidence"),
        sort=request.args.get("sort", "newest"),
        limit=int(request.args.get("limit", 500)),
    ))


@threats_bp.get("/<threat_id>")
def threat_detail(threat_id):
    t = get_threat(threat_id)
    if not t:
        return jsonify({"error": "not found"}), 404
    return jsonify(t)


@threats_bp.post("/<threat_id>/notes")
def create_note(threat_id):
    data = request.get_json(silent=True) or {}
    note = (data.get("note") or "").strip()
    if not note or len(note) > 2000:
        return jsonify({"error": "invalid note"}), 400
    add_note(threat_id, note)
    return jsonify({"ok": True}), 201