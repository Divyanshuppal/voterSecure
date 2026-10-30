import os
import secrets
import time
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from database import (
    initialize_database, seed_demo_data, get_connection,
    add_audit_log, verify_audit_chain
)
from voting import cast_vote, verify_receipt

app = Flask(__name__)
app.secret_key = os.environ.get("VOTESECURE_SECRET", "change-this-demo-secret-before-deployment")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

OTP_VALIDITY_SECONDS = 300  # 5 minutes
ADMIN_PASSWORD = os.environ.get("VOTESECURE_ADMIN_PASSWORD", "admin123")


@app.context_processor
def inject_globals():
    return {"project_name": "VoteSecure"}


def student_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "student_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin login is required.", "warning")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def home():
    if session.get("student_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/generate-otp", methods=["POST"])
def generate_otp():
    """Generate a one-time password and display it in the server terminal."""
    student_id = request.form.get("student_id", "").strip().upper()

    if not student_id:
        flash("Enter your College ID first.", "warning")
        return redirect(url_for("login"))

    conn = get_connection()
    student = conn.execute(
        "SELECT student_id FROM students WHERE student_id = ?",
        (student_id,)
    ).fetchone()
    conn.close()

    if student is None:
        add_audit_log("OTP_REQUEST_FAILED", {
            "student_id": student_id, "reason": "unknown_id"
        })
        flash("This College ID is not registered.", "danger")
        return redirect(url_for("login"))

    otp = str(secrets.randbelow(900000) + 100000)
    session["pending_student_id"] = student_id
    session["login_otp"] = otp
    session["otp_created_at"] = time.time()

    # Demo delivery: the OTP is printed in the terminal running Flask.
    print("\\n" + "=" * 48)
    print(" VoteSecure - OTP GENERATED")
    print(f" College ID : {student_id}")
    print(f" OTP        : {otp}")
    print(" Valid for  : 5 minutes")
    print("=" * 48 + "\\n", flush=True)

    add_audit_log("OTP_GENERATED", {"student_id": student_id})
    flash("OTP generated. Check the terminal where you started VoteSecure.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip().upper()
        otp = request.form.get("otp", "").strip()

        if not student_id or not otp:
            flash("Enter both College ID and OTP.", "danger")
            return render_template("login.html")

        pending_id = session.get("pending_student_id")
        saved_otp = session.get("login_otp")
        created_at = session.get("otp_created_at", 0)

        if pending_id != student_id or not saved_otp:
            flash("Please generate an OTP for this College ID first.", "warning")
            return render_template("login.html")

        if time.time() - created_at > OTP_VALIDITY_SECONDS:
            session.pop("login_otp", None)
            session.pop("otp_created_at", None)
            flash("OTP expired. Generate a new OTP.", "warning")
            return render_template("login.html")

        if not secrets.compare_digest(otp, saved_otp):
            add_audit_log("LOGIN_FAILED", {"student_id": student_id, "reason": "wrong_otp"})
            flash("Incorrect OTP. Please try again.", "danger")
            return render_template("login.html")

        conn = get_connection()
        student = conn.execute(
            "SELECT student_id, name FROM students WHERE student_id = ?",
            (student_id,)
        ).fetchone()
        conn.close()

        if student is None:
            flash("This College ID is not registered.", "danger")
            return render_template("login.html")

        # OTP is one-time use: remove it after successful verification.
        session.clear()
        session["student_id"] = student["student_id"]
        session["student_name"] = student["name"]
        add_audit_log("LOGIN_SUCCESS", {"student_id": student_id})
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
@student_required
def dashboard():
    conn = get_connection()
    student = conn.execute(
        "SELECT name, has_voted FROM students WHERE student_id = ?",
        (session["student_id"],)
    ).fetchone()
    election = conn.execute(
        "SELECT value FROM settings WHERE key = 'election_open'"
    ).fetchone()
    conn.close()

    if student is None:
        session.clear()
        flash("Student account was not found.", "danger")
        return redirect(url_for("login"))

    election_open = bool(int(election["value"])) if election else True
    return render_template(
        "dashboard.html",
        name=student["name"],
        student_id=session["student_id"],
        has_voted=bool(student["has_voted"]),
        election_open=election_open
    )


@app.route("/vote", methods=["GET", "POST"])
@student_required
def vote():
    conn = get_connection()
    election = conn.execute(
        "SELECT value FROM settings WHERE key = 'election_open'"
    ).fetchone()
    candidates = conn.execute(
        "SELECT candidate_id, name, description FROM candidates ORDER BY candidate_id"
    ).fetchall()
    student = conn.execute(
        "SELECT has_voted FROM students WHERE student_id = ?",
        (session["student_id"],)
    ).fetchone()
    conn.close()

    election_open = bool(int(election["value"])) if election else True

    if not election_open:
        flash("Voting is currently closed.", "warning")
        return redirect(url_for("dashboard"))

    if student is None or student["has_voted"]:
        flash("Your account has already voted or is not eligible.", "warning")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        try:
            candidate_id = int(request.form.get("candidate_id", ""))
        except ValueError:
            flash("Please select a valid candidate.", "danger")
            return render_template("vote.html", candidates=candidates)

        try:
            receipt_token = cast_vote(session["student_id"], candidate_id)
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("dashboard"))

        session["new_receipt"] = receipt_token
        return redirect(url_for("receipt"))

    return render_template("vote.html", candidates=candidates)


@app.route("/receipt")
@student_required
def receipt():
    token = session.pop("new_receipt", None)
    if not token:
        flash("A new receipt is shown only immediately after voting. Use Verify Receipt to check an existing receipt.", "info")
        return redirect(url_for("verify"))
    return render_template("receipt.html", token=token)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    result = None
    if request.method == "POST":
        token = request.form.get("receipt_token", "").strip()
        if token:
            result = verify_receipt(token)
        else:
            flash("Enter your receipt code.", "warning")
    return render_template("verify.html", result=result)


@app.route("/results")
def results():
    conn = get_connection()
    election = conn.execute(
        "SELECT value FROM settings WHERE key = 'election_open'"
    ).fetchone()
    is_open = bool(int(election["value"])) if election else True
    rows = conn.execute("""
        SELECT c.name, COUNT(v.ballot_id) AS vote_count
        FROM candidates c
        LEFT JOIN votes v ON c.candidate_id = v.candidate_id
        GROUP BY c.candidate_id, c.name
        ORDER BY vote_count DESC, c.name
    """).fetchall()
    total = conn.execute("SELECT COUNT(*) AS n FROM votes").fetchone()["n"]
    conn.close()
    return render_template("results.html", rows=rows, total=total, election_open=is_open)


@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        password = request.form.get("password", "")
        if secrets.compare_digest(password, ADMIN_PASSWORD):
            session["is_admin"] = True
            add_audit_log("ADMIN_LOGIN", {"result": "success"})
            return redirect(url_for("admin_dashboard"))
        flash("Incorrect admin password.", "danger")
    return render_template("admin_login.html")


@app.route("/admin/dashboard", methods=["GET", "POST"])
@admin_required
def admin_dashboard():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "toggle_election":
            new_value = request.form.get("election_open") == "1"
            conn = get_connection()
            conn.execute(
                "UPDATE settings SET value = ? WHERE key = 'election_open'",
                ("1" if new_value else "0",)
            )
            conn.commit()
            conn.close()
            add_audit_log("ELECTION_STATUS_CHANGED", {"open": new_value})
            flash("Election status updated.", "success")
        elif action == "add_candidate":
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            if name:
                conn = get_connection()
                conn.execute(
                    "INSERT INTO candidates (name, description) VALUES (?, ?)",
                    (name, description)
                )
                conn.commit()
                conn.close()
                add_audit_log("CANDIDATE_ADDED", {"candidate_name": name})
                flash("Candidate added.", "success")
            else:
                flash("Candidate name is required.", "danger")
        return redirect(url_for("admin_dashboard"))

    conn = get_connection()
    candidates = conn.execute(
        "SELECT candidate_id, name, description FROM candidates ORDER BY candidate_id"
    ).fetchall()
    students = conn.execute(
        "SELECT student_id, name, has_voted FROM students ORDER BY student_id"
    ).fetchall()
    election = conn.execute(
        "SELECT value FROM settings WHERE key = 'election_open'"
    ).fetchone()
    logs = conn.execute(
        "SELECT log_id, event, details, created_at, entry_hash FROM audit_logs ORDER BY log_id DESC LIMIT 15"
    ).fetchall()
    total_votes = conn.execute("SELECT COUNT(*) AS n FROM votes").fetchone()["n"]
    conn.close()

    chain_ok, chain_message = verify_audit_chain()
    return render_template(
        "admin_dashboard.html",
        candidates=candidates,
        students=students,
        election_open=bool(int(election["value"])) if election else True,
        logs=logs,
        total_votes=total_votes,
        chain_ok=chain_ok,
        chain_message=chain_message
    )


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/results")
def api_results():
    conn = get_connection()
    rows = conn.execute("""
        SELECT c.name, COUNT(v.ballot_id) AS votes
        FROM candidates c
        LEFT JOIN votes v ON c.candidate_id = v.candidate_id
        GROUP BY c.candidate_id, c.name
        ORDER BY c.candidate_id
    """).fetchall()
    conn.close()
    return {
        "results": [{"candidate": r["name"], "votes": r["votes"]} for r in rows]
    }


@app.route("/api/audit/verify")
def api_audit_verify():
    ok, message = verify_audit_chain()
    return {"valid": ok, "message": message}


with app.app_context():
    initialize_database()
    seed_demo_data()


if __name__ == "__main__":
    app.run(debug=True)
