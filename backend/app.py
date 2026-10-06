"""
backend/app.py
Flask entry point for the Cybersecurity Awareness & Threat Intelligence Dashboard.
"""
import os

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

from backend.db import init_db, seed_from_csv
from backend.services.alert_engine import persist_alerts_from_threats
from backend.routes.threats import threats_bp
from backend.routes.indicators import indicators_bp
from backend.routes.alerts import alerts_bp
from backend.routes.vulnerabilities import vulns_bp
from backend.routes.dashboard import dashboard_bp
from backend.routes.awareness import awareness_bp
from backend.routes.quiz import quiz_bp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND = os.path.join(ROOT, "frontend")

app = Flask(__name__, static_folder=FRONTEND, static_url_path="")
CORS(app)

app.register_blueprint(threats_bp)
app.register_blueprint(indicators_bp)
app.register_blueprint(alerts_bp)
app.register_blueprint(vulns_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(awareness_bp)
app.register_blueprint(quiz_bp)


@app.get("/")
def index():
    return send_from_directory(FRONTEND, "index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "project": "CyberAwareness-TI-Dashboard"})


if __name__ == "__main__":
    init_db()
    seed_from_csv()
    persist_alerts_from_threats()
    app.run(host="127.0.0.1", port=5000, debug=True)