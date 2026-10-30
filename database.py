import os
import sqlite3
import json
import hashlib
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "votesecure.db")


def get_connection():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS students (
            student_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            has_voted INTEGER NOT NULL DEFAULT 0 CHECK (has_voted IN (0,1))
        );

        CREATE TABLE IF NOT EXISTS candidates (
            candidate_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS votes (
            ballot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (candidate_id) REFERENCES candidates(candidate_id)
        );

        CREATE TABLE IF NOT EXISTS receipts (
            receipt_id INTEGER PRIMARY KEY AUTOINCREMENT,
            ballot_id INTEGER NOT NULL UNIQUE,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            FOREIGN KEY (ballot_id) REFERENCES votes(ballot_id)
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            details TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES ('election_open', '1')"
    )
    conn.commit()
    conn.close()


def seed_demo_data():
    conn = get_connection()
    students = [
        ("STU001", "Aarav Sharma"),
        ("STU002", "Diya Singh"),
        ("STU003", "Kabir Kumar"),
        ("STU004", "Meera Kaur"),
        ("STU005", "Arjun Verma"),
        ("STU006", "Simran Gill"),
        ("STU007", "Ishaan Patel"),
        ("STU008", "Ananya Gupta"),
        ("STU009", "Rohan Das"),
        ("STU010", "Navya Joshi"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO students (student_id, name) VALUES (?, ?)",
        students
    )

    candidates = [
        ("Candidate A", "Focused on student welfare and development."),
        ("Candidate B", "Focused on better campus facilities."),
        ("Candidate C", "Focused on student activities and events."),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO candidates (name, description) VALUES (?, ?)",
        candidates
    )
    conn.commit()
    conn.close()


def add_audit_log(event, details):
    conn = get_connection()
    previous = conn.execute(
        "SELECT entry_hash FROM audit_logs ORDER BY log_id DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["entry_hash"] if previous else "GENESIS"
    created_at = datetime.now(timezone.utc).isoformat()
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
    payload = f"{previous_hash}|{event}|{details_json}|{created_at}"
    entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    conn.execute("""
        INSERT INTO audit_logs
        (event, details, previous_hash, entry_hash, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (event, details_json, previous_hash, entry_hash, created_at))
    conn.commit()
    conn.close()


def verify_audit_chain():
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM audit_logs ORDER BY log_id"
    ).fetchall()
    conn.close()

    previous_hash = "GENESIS"
    for row in rows:
        if row["previous_hash"] != previous_hash:
            return False, f"Broken previous-hash link at log #{row['log_id']}."
        payload = (
            f"{previous_hash}|{row['event']}|{row['details']}|{row['created_at']}"
        )
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if expected != row["entry_hash"]:
            return False, f"Hash mismatch at log #{row['log_id']}."
        previous_hash = row["entry_hash"]

    return True, f"Audit chain valid ({len(rows)} records checked)."
