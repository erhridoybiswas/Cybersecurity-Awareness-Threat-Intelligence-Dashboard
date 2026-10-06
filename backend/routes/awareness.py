import json
import os
from flask import Blueprint, jsonify

awareness_bp = Blueprint("awareness", __name__, url_prefix="/api/awareness")
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODULES_PATH = os.path.join(ROOT, "awareness", "modules.json")


@awareness_bp.get("/modules")
def modules():
    with open(MODULES_PATH, encoding="utf-8") as f:
        return jsonify(json.load(f))