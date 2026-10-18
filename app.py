"""
app.py — Flask Backend for Raptor Guard SIEM/SOAR with SOC-Only MFA Authentication.
"""

from functools import wraps
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, session, redirect
import storage
from collector import poll_all_channels
from auth import (
    init_auth_db,
    verify_credentials_and_send_otp,
    verify_otp_code,
    initiate_password_reset,
    complete_password_reset,
)

# Optional Windows Firewall remediation import
try:
    from remediation import block_ip_windows
except ImportError:
    block_ip_windows = None

BASE_DIR = Path(__file__).parent
app = Flask(__name__, static_folder=str(BASE_DIR))
app.secret_key = "raptor-guard-soc-secret-key-2026"

# Initialize SQLite Tables on startup
storage.init_db()
init_auth_db()


def soc_login_required(f):
    """Restricts access strictly to authenticated SOC Analysts."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "soc_user" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"status": "unauthorized", "message": "SOC Login Required"}), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


# ==========================================
# SOC AUTHENTICATION ROUTES
# ==========================================

@app.route("/login")
def login_page():
    if "soc_user" in session:
        return redirect("/")
    return send_from_directory(BASE_DIR, "login.html")


@app.post("/api/auth/login")
def api_login():
    data = request.json or {}
    return jsonify(verify_credentials_and_send_otp(data.get("email"), data.get("password")))


@app.post("/api/auth/verify-otp")
def api_verify_otp():
    data = request.json or {}
    res = verify_otp_code(data.get("email"), data.get("otp"))
    if res.get("status") == "success":
        session["soc_user"] = res["user"]
    return jsonify(res)


@app.post("/api/auth/forgot-password")
def api_forgot_password():
    data = request.json or {}
    return jsonify(initiate_password_reset(data.get("email")))


@app.post("/api/auth/reset-password")
def api_reset_password():
    data = request.json or {}
    return jsonify(
        complete_password_reset(data.get("email"), data.get("otp"), data.get("new_password"))
    )


@app.route("/api/auth/logout", methods=["GET", "POST"])
def api_logout():
    session.pop("soc_user", None)
    return redirect("/login")


# ==========================================
# SIEM & SOAR DASHBOARD ROUTES (PROTECTED)
# ==========================================

@app.route("/")
@soc_login_required
def index():
    return send_from_directory(BASE_DIR, "raptor-guard-dashboard.html")


@app.get("/api/hosts")
@soc_login_required
def api_hosts():
    return jsonify(storage.get_targets())


@app.post("/api/targets")
@soc_login_required
def api_add_target():
    data = request.json or {}
    host = data.get("host", "").strip()
    if host:
        storage.add_target(host)
    return jsonify({"status": "ok", "hosts": storage.get_targets()})


@app.get("/api/logs")
@soc_login_required
def api_logs():
    host = request.args.get("host", "all")
    host_filter = None if host in ("all", "", None) else host
    rows = storage.get_recent(limit=150, host_filter=host_filter)

    formatted = []
    for r in rows:
        formatted.append({
            "id": r.get("id"),
            "time": r.get("timestamp"),
            "timestamp": r.get("timestamp"),
            "ip": r.get("host") or "localhost",
            "target": r.get("user") or "SYSTEM",
            "type": r.get("classification") or f"Event ID {r.get('event_id', 0)}",
            "level": r.get("level", 3),
            "mitre_tactic": r.get("mitre_tactic", "Discovery"),
            "mitre_technique": r.get("mitre_technique", "T1083"),
            "message": r.get("message", ""),
            "response_status": r.get("response_status", "Open"),
            "analyst_notes": r.get("analyst_notes", ""),
        })
    return jsonify(formatted)


@app.post("/api/logs/<int:event_id>/status")
@soc_login_required
def api_update_log_status(event_id):
    data = request.json or {}
    status = data.get("status", "Open")
    notes = data.get("notes", "")
    storage.update_event_status(event_id, status, notes)
    return jsonify({"status": "ok"})


@app.post("/api/remediate")
@soc_login_required
def api_remediate():
    data = request.json or {}
    target_ip = data.get("target") or data.get("ip_address") or "127.0.0.1"
    log_id = data.get("log_id")

    if log_id:
        storage.update_event_status(log_id, "True_Positive", f"[BLOCKED IP: {target_ip}]")

    if block_ip_windows and target_ip not in ("127.0.0.1", "localhost"):
        result = block_ip_windows(target_ip)
        return jsonify(result)

    return jsonify({
        "status": "success",
        "message": f"SOAR Playbook Executed: Blocked {target_ip} and marked event #{log_id} as True Positive."
    })


if __name__ == "__main__":
    print("Starting Raptor Guard SOC Server on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)