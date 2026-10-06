from flask import Blueprint, jsonify, request

from backend.services.ioc_validator import validate_indicator
from backend.services.enrichment_engine import enrich_indicator
from backend.services.threat_service import search_indicator

indicators_bp = Blueprint("indicators", __name__, url_prefix="/api/indicators")


@indicators_bp.get("/validate")
def validate():
    value = request.args.get("value", "")
    return jsonify(validate_indicator(value))


@indicators_bp.get("/search")
def search():
    value = request.args.get("value", "").strip()
    if not value:
        return jsonify({"error": "missing value"}), 400
    return jsonify({
        "validation": validate_indicator(value),
        "lookup": search_indicator(value),
        "enrichment": enrich_indicator(value),
        "note": "Lookup only. No network contact is performed.",
    })