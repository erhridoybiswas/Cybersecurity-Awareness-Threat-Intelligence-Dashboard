"""
tests/test_all.py
Automated tests for the dashboard.

Run:  pytest -v
"""
import os
import sys
import json
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Force a temporary DB file BEFORE importing backend modules
os.environ["PYTEST_RUN"] = "1"
import backend.db as db_module

TEST_DB = os.path.join(tempfile.gettempdir(), "test_threat_intel.db")
db_module.DB_PATH = TEST_DB
if os.path.exists(TEST_DB):
    os.remove(TEST_DB)

from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_threat_risk, classify_risk
from backend.services.attack_mapper import map_category_to_tactics
from backend.routes.vulnerabilities import calculate_vulnerability_priority
from backend.db import init_db, get_connection
from backend.app import app


@pytest.fixture(scope="module", autouse=True)
def _setup_db():
    init_db()
    yield


@pytest.fixture()
def client():
    return app.test_client()


# ---------- 1-11: IOC VALIDATION ----------
def test_01_valid_ipv4():           assert validate_indicator("198.51.100.25")["valid"]
def test_02_invalid_ipv4():         assert not validate_indicator("999.1.1.1")["valid"]
def test_03_valid_ipv6():           assert validate_indicator("2001:db8::1")["valid"]
def test_04_valid_domain():         assert validate_indicator("example.com")["valid"]
def test_05_invalid_domain():       assert not validate_indicator("not a domain!!")["valid"]
def test_06_valid_url():            assert validate_indicator("https://example.com/login")["valid"]
def test_07_valid_md5():            assert validate_indicator("a"*32)["valid"]
def test_08_valid_sha1():           assert validate_indicator("b"*40)["valid"]
def test_09_valid_sha256():         assert validate_indicator("c"*64)["valid"]
def test_10_valid_cve():            assert validate_indicator("CVE-2026-12345")["valid"]
def test_11_invalid_cve():          assert not validate_indicator("CVE-XX-1")["valid"]


# ---------- 12-15: RISK ----------
def test_12_risk_class_low():       assert classify_risk(15) == "INFORMATIONAL"
def test_13_risk_class_crit():      assert classify_risk(95) == "CRITICAL"
def test_14_risk_score_range():
    r = calculate_threat_risk("HIGH", 80, 2, 5, "A", 2)
    assert 0 <= r["risk_score"] <= 100
def test_15_higher_severity_higher_risk():
    a = calculate_threat_risk("LOW", 50, 5, 2, "B", 0)["risk_score"]
    b = calculate_threat_risk("CRITICAL", 50, 5, 2, "B", 0)["risk_score"]
    assert b > a


# ---------- 16-19: ATT&CK / VULN ----------
def test_16_attack_mapping_phishing():
    assert "Initial Access" in map_category_to_tactics("PHISHING")
def test_17_attack_mapping_unknown():
    assert map_category_to_tactics("UNKNOWN") == []
def test_18_vuln_priority_higher_when_internet():
    a = calculate_vulnerability_priority(7.0, "MEDIUM", "INTERNAL",
                                         "NO_KNOWN", "MEDIUM")
    b = calculate_vulnerability_priority(7.0, "MEDIUM", "INTERNET",
                                         "NO_KNOWN", "MEDIUM")
    assert b > a
def test_19_vuln_priority_exploited_higher():
    a = calculate_vulnerability_priority(7.0, "MEDIUM", "INTERNET",
                                         "NO_KNOWN", "MEDIUM")
    b = calculate_vulnerability_priority(7.0, "MEDIUM", "INTERNET",
                                         "OBSERVED_IN_WILD", "MEDIUM")
    assert b > a


# ---------- 20-24: DB / API ----------
def test_20_health(client):
    assert client.get("/api/health").status_code == 200

def test_21_dashboard_stats(client):
    r = client.get("/api/dashboard/stats")
    assert r.status_code == 200
    assert "total_threats" in r.get_json()

def test_22_threats_list(client):
    r = client.get("/api/threats?limit=5")
    assert r.status_code == 200
    assert isinstance(r.get_json(), list)

def test_23_indicator_search_unknown(client):
    r = client.get("/api/indicators/search?value=nonexistent.invalid")
    assert r.status_code == 200
    assert r.get_json()["lookup"]["found"] is False

def test_24_indicator_validate(client):
    r = client.get("/api/indicators/validate?value=198.51.100.25")
    assert r.get_json()["valid"] is True


# ---------- 25-30: AWARENESS / QUIZ ----------
def test_25_modules_exist(client):
    r = client.get("/api/awareness/modules")
    assert r.status_code == 200
    assert len(r.get_json()) >= 15

def test_26_quiz_load(client):
    r = client.get("/api/quiz")
    data = r.get_json()
    assert len(data) >= 30
    assert "correct" not in data[0]  # answers hidden

def test_27_quiz_submit_all_wrong(client):
    r = client.post("/api/quiz/submit",
                    json={"answers": {str(i): "Z" for i in range(1, 31)}})
    assert r.get_json()["overall_score"] == 0

def test_28_quiz_submit_perfect(client):
    qs = json.load(open(os.path.join(ROOT, "awareness", "quiz_questions.json"),
                        encoding="utf-8"))
    answers = {str(q["id"]): q["correct"] for q in qs}
    r = client.post("/api/quiz/submit", json={"answers": answers})
    assert r.get_json()["overall_score"] == 100

def test_29_quiz_recommendations_present(client):
    r = client.post("/api/quiz/submit", json={"answers": {}})
    assert "recommendations" in r.get_json()

def test_30_alerts_list(client):
    r = client.get("/api/alerts")
    assert r.status_code == 200


# ---------- 31-35: FILTERS / SORTING / NOTES / DB ----------
def test_31_filter_severity(client):
    r = client.get("/api/threats?severity=CRITICAL&limit=5")
    for row in r.get_json():
        assert row["severity"] == "CRITICAL"

def test_32_sort_risk(client):
    r = client.get("/api/threats?sort=risk&limit=10")
    scores = [x["risk_score"] for x in r.get_json()]
    assert scores == sorted(scores, reverse=True)

def test_33_create_note(client):
    # find any threat
    rows = client.get("/api/threats?limit=1").get_json()
    if not rows:
        pytest.skip("no threats in test DB")
    tid = rows[0]["threat_id"]
    r = client.post(f"/api/threats/{tid}/notes", json={"note": "test note"})
    assert r.status_code == 201

def test_34_invalid_note_rejected(client):
    rows = client.get("/api/threats?limit=1").get_json()
    if not rows:
        pytest.skip("no threats in test DB")
    tid = rows[0]["threat_id"]
    r = client.post(f"/api/threats/{tid}/notes", json={"note": ""})
    assert r.status_code == 400

def test_35_db_persistence():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM threats")
    assert cur.fetchone()[0] >= 0
    conn.close()