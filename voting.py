import hashlib
import secrets
from datetime import datetime, timezone
from database import get_connection, add_audit_log


def cast_vote(student_id, candidate_id):
    """
    Records an anonymous ballot and marks the student as having voted.
    Student ID is deliberately not stored in the votes or receipts tables.
    """
    token = secrets.token_urlsafe(24)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    created_at = datetime.now(timezone.utc).isoformat()

    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")

        election = conn.execute(
            "SELECT value FROM settings WHERE key = 'election_open'"
        ).fetchone()
        if not election or election["value"] != "1":
            raise ValueError("The election is closed.")

        candidate = conn.execute(
            "SELECT candidate_id FROM candidates WHERE candidate_id = ?",
            (candidate_id,)
        ).fetchone()
        if candidate is None:
            raise ValueError("The selected candidate does not exist.")

        updated = conn.execute(
            "UPDATE students SET has_voted = 1 WHERE student_id = ? AND has_voted = 0",
            (student_id,)
        )
        if updated.rowcount != 1:
            raise ValueError("You have already voted or are not eligible.")

        cursor = conn.execute(
            "INSERT INTO votes (candidate_id, created_at) VALUES (?, ?)",
            (candidate_id, created_at)
        )
        ballot_id = cursor.lastrowid

        conn.execute(
            "INSERT INTO receipts (ballot_id, token_hash, created_at) VALUES (?, ?, ?)",
            (ballot_id, token_hash, created_at)
        )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    # This audit event contains no voter ID or candidate choice.
    add_audit_log("BALLOT_ACCEPTED", {"ballot_reference": ballot_id})
    return token


def verify_receipt(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn = get_connection()
    row = conn.execute("""
        SELECT r.created_at
        FROM receipts r
        WHERE r.token_hash = ?
    """, (token_hash,)).fetchone()
    conn.close()

    if row:
        return {
            "valid": True,
            "message": "Your ballot receipt is valid. The ballot is recorded.",
            "created_at": row["created_at"]
        }

    return {
        "valid": False,
        "message": "Receipt not found. Check the code and try again.",
        "created_at": None
    }
