"""
backend/db.py
SQLite schema and CSV -> DB seeding for the dashboard.
"""
import csv
import os
import sqlite3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(ROOT, "data", "threat_intel.db")
THREAT_CSV = os.path.join(ROOT, "data", "threat_intelligence_dataset.csv")
VULN_CSV = os.path.join(ROOT, "data", "vulnerabilities.csv")

SCHEMA = """
CREATE TABLE IF NOT EXISTS threats (
    threat_id          TEXT PRIMARY KEY,
    threat_name        TEXT NOT NULL,
    category           TEXT NOT NULL,
    description        TEXT,
    severity           TEXT NOT NULL,
    risk_score         REAL,
    confidence_score   INTEGER,
    status             TEXT,
    source_name        TEXT,
    source_reliability TEXT,
    first_seen         TEXT,
    last_seen          TEXT,
    region             TEXT,
    mitre_tactic       TEXT,
    mitre_technique    TEXT,
    mitre_technique_id TEXT,
    cve_id             TEXT
);

CREATE TABLE IF NOT EXISTS indicators (
    indicator_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id       TEXT,
    indicator_type  TEXT,
    indicator_value TEXT,
    first_seen      TEXT,
    last_seen       TEXT,
    FOREIGN KEY (threat_id) REFERENCES threats(threat_id)
);

CREATE TABLE IF NOT EXISTS sources (
    source_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT UNIQUE,
    reliability TEXT
);

CREATE TABLE IF NOT EXISTS attack_mappings (
    mapping_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id    TEXT,
    tactic       TEXT,
    technique    TEXT,
    technique_id TEXT,
    FOREIGN KEY (threat_id) REFERENCES threats(threat_id)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id           TEXT UNIQUE,
    product_category TEXT,
    severity         TEXT,
    cvss_score       REAL,
    patch_available  TEXT,
    exploitation_status TEXT,
    published_date   TEXT,
    priority_score   REAL,
    description      TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id       TEXT,
    timestamp       TEXT,
    alert_type      TEXT,
    severity        TEXT,
    risk_score      REAL,
    confidence_score INTEGER,
    description     TEXT,
    status          TEXT,
    observation_count INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS analyst_notes (
    note_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id  TEXT,
    note       TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS awareness_modules (
    module_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title     TEXT,
    category  TEXT
);

CREATE TABLE IF NOT EXISTS quiz_results (
    result_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    anonymous_user_id TEXT,
    overall_score     INTEGER,
    category_scores   TEXT,
    created_at        TEXT
);

CREATE INDEX IF NOT EXISTS idx_threat_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threat_category ON threats(category);
CREATE INDEX IF NOT EXISTS idx_ind_value ON indicators(indicator_value);
CREATE INDEX IF NOT EXISTS idx_ind_type ON indicators(indicator_type);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
"""


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print("[+] Database schema initialized.")


def seed_from_csv():
    if not os.path.exists(THREAT_CSV):
        print("[!] Threat CSV missing. Run data/generate_threat_data.py first.")
        return
    conn = get_connection()
    cur = conn.cursor()

    # Threats
    with open(THREAT_CSV, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cur.execute(
                """INSERT OR REPLACE INTO threats VALUES
                (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row["threat_id"], row["threat_name"], row["threat_category"],
                    row["description"], row["severity"], float(row["risk_score"]),
                    int(row["confidence_score"]), row["status"], row["source_name"],
                    row["source_reliability"], row["first_seen"], row["last_seen"],
                    row["country_or_region_optional"], row["mitre_tactic_optional"],
                    row["mitre_technique_optional"], row["mitre_technique_id_optional"],
                    row["cve_id_optional"],
                ),
            )
            cur.execute(
                "INSERT INTO indicators (threat_id, indicator_type, indicator_value, first_seen, last_seen) VALUES (?,?,?,?,?)",
                (row["threat_id"], row["indicator_type"], row["indicator_value"],
                 row["first_seen"], row["last_seen"]),
            )
            if row["mitre_tactic_optional"] and row["mitre_tactic_optional"] != "N/A":
                cur.execute(
                    "INSERT INTO attack_mappings (threat_id, tactic, technique, technique_id) VALUES (?,?,?,?)",
                    (row["threat_id"], row["mitre_tactic_optional"],
                     row["mitre_technique_optional"], row["mitre_technique_id_optional"]),
                )

    # Sources
    for name, rel in [("Internal SOC", "A"), ("Security Vendor", "B"),
                      ("Public Threat Feed", "C"), ("Research Report", "B"),
                      ("Community Submission", "D"), ("Unknown Source", "D")]:
        cur.execute("INSERT OR IGNORE INTO sources (source_name, reliability) VALUES (?,?)",
                    (name, rel))

    # Vulnerabilities
    if os.path.exists(VULN_CSV):
        with open(VULN_CSV, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cur.execute(
                    """INSERT OR REPLACE INTO vulnerabilities
                    (cve_id, product_category, severity, cvss_score,
                     patch_available, exploitation_status, published_date,
                     priority_score, description)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        row["cve_id"], row["product_category"], row["severity"],
                        float(row["cvss_score"]), row["patch_available"],
                        row["exploitation_status_demo"], row["published_date"],
                        0.0, row["description"],
                    ),
                )

    conn.commit()
    conn.close()
    print("[+] Database seeded from CSV.")


if __name__ == "__main__":
    init_db()
    seed_from_csv()