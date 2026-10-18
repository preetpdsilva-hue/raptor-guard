"""
auth.py — Enterprise SOC-Only Authentication & Email OTP Engine for Raptor Guard.
"""

import sqlite3
import hashlib
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = Path(__file__).parent / "events.db"

# =====================================================================
# OPTIONAL SMTP CONFIGURATION (For real Email delivery)
# Leave blank during testing to read OTPs directly from the terminal!
# =====================================================================
SMTP_EMAIL = ""          # e.g., "your.email@gmail.com"
SMTP_APP_PASSWORD = ""   # 16-character Google App Password
DEFAULT_SOC_EMAIL = "soc@raptorguard.local"
DEFAULT_SOC_PASS = "RaptorSOC@2026"


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
    ).hex()
    return pw_hash, salt


def init_auth_db():
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS soc_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            role TEXT DEFAULT 'Tier-3 SOC Lead',
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            otp_code TEXT,
            otp_expiry TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT
        )
        """
    )
    # Seed authorized SOC Analyst account if none exists
    cur = conn.execute("SELECT COUNT(*) as cnt FROM soc_users")
    if cur.fetchone()["cnt"] == 0:
        pw_hash, salt = hash_password(DEFAULT_SOC_PASS)
        conn.execute(
            """
            INSERT INTO soc_users (email, name, role, password_hash, salt)
            VALUES (?, ?, ?, ?, ?)
            """,
            (DEFAULT_SOC_EMAIL.lower(), "Preet Dsilva", "SOC Lead Analyst", pw_hash, salt),
        )
        print(f"\n[SOC AUTH] Provisioned Default SOC Account:")
        print(f" -> Email:    {DEFAULT_SOC_EMAIL}")
        print(f" -> Password: {DEFAULT_SOC_PASS}\n")
    conn.commit()
    conn.close()


def send_otp_email(recipient_email: str, otp_code: str, purpose: str = "MFA Login"):
    """Prints OTP to terminal (fail-safe for live demos) and sends via SMTP if configured."""
    print("\n" + "=" * 62)
    print(f" [RAPTOR GUARD SOC SECURITY — {purpose.upper()} OTP]")
    print(f" Authorized Analyst : {recipient_email}")
    print(f" 6-Digit OTP Code   : {otp_code}  (Valid for 5 minutes)")
    print("=" * 62 + "\n")

    if not SMTP_EMAIL or not SMTP_APP_PASSWORD:
        return True

    try:
        msg = EmailMessage()
        msg["Subject"] = f"[Raptor Guard SOC] { otp_code } is your {purpose} verification code"
        msg["From"] = f"Raptor Guard SOC <{SMTP_EMAIL}>"
        msg["To"] = recipient_email
        msg.set_content(
            f"Raptor Guard Security Operations Center (SOC)\n\n"
            f"Your 6-digit verification OTP for {purpose} is: {otp_code}\n\n"
            f"This code expires in 5 minutes. If you did not request this, "
            f"an unauthorized login attempt was made on your SOC account."
        )
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=5) as server:
            server.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"[SMTP Notice] Email skipped ({e}). Use the terminal OTP above.")
        return True


def verify_credentials_and_send_otp(email: str, password: str) -> dict:
    email = (email or "").strip().lower()
    conn = get_connection()
    user = conn.execute("SELECT * FROM soc_users WHERE email = ?", (email,)).fetchone()

    if not user:
        conn.close()
        return {"status": "error", "message": "Access Denied: Unauthorized email. SOC Personnel Only."}

    # Check account lockout
    if user["locked_until"]:
        lock_time = datetime.fromisoformat(user["locked_until"])
        if datetime.now() < lock_time:
            conn.close()
            return {"status": "error", "message": "SOC Account temporarily locked due to failed attempts. Try again in 5 minutes."}

    pw_hash, _ = hash_password(password, user["salt"])
    if pw_hash != user["password_hash"]:
        fails = user["failed_attempts"] + 1
        locked_until = (datetime.now() + timedelta(minutes=5)).isoformat() if fails >= 5 else None
        conn.execute(
            "UPDATE soc_users SET failed_attempts = ?, locked_until = ? WHERE email = ?",
            (fails, locked_until, email),
        )
        conn.commit()
        conn.close()
        return {"status": "error", "message": f"Invalid credentials. ({max(0, 5 - fails)} attempts remaining)"}

    # Generate 6-digit cryptographic OTP
    otp = f"{secrets.randbelow(900000) + 100000}"
    expiry = (datetime.now() + timedelta(minutes=5)).isoformat()

    conn.execute(
        "UPDATE soc_users SET otp_code = ?, otp_expiry = ?, failed_attempts = 0, locked_until = NULL WHERE email = ?",
        (otp, expiry, email),
    )
    conn.commit()
    conn.close()

    send_otp_email(email, otp, purpose="SOC MFA Login")
    return {"status": "otp_sent", "message": "Credentials verified. 6-digit OTP dispatched to SOC email."}


def verify_otp_code(email: str, otp_code: str) -> dict:
    email = (email or "").strip().lower()
    otp_code = (otp_code or "").strip()
    conn = get_connection()
    user = conn.execute("SELECT * FROM soc_users WHERE email = ?", (email,)).fetchone()

    if not user or not user["otp_code"]:
        conn.close()
        return {"status": "error", "message": "No active OTP request found. Please sign in again."}

    if datetime.now() > datetime.fromisoformat(user["otp_expiry"]):
        conn.close()
        return {"status": "error", "message": "OTP has expired. Please request a new code."}

    if not secrets.compare_digest(user["otp_code"], otp_code):
        conn.close()
        return {"status": "error", "message": "Invalid 6-digit OTP code."}

    # Clear OTP after successful verification
    conn.execute("UPDATE soc_users SET otp_code = NULL, otp_expiry = NULL WHERE email = ?", (email,))
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "user": {"email": user["email"], "name": user["name"], "role": user["role"]},
    }


def initiate_password_reset(email: str) -> dict:
    email = (email or "").strip().lower()
    conn = get_connection()
    user = conn.execute("SELECT * FROM soc_users WHERE email = ?", (email,)).fetchone()

    if not user:
        conn.close()
        return {"status": "error", "message": "Access Denied: Email is not registered in the SOC directory."}

    otp = f"{secrets.randbelow(900000) + 100000}"
    expiry = (datetime.now() + timedelta(minutes=5)).isoformat()

    conn.execute("UPDATE soc_users SET otp_code = ?, otp_expiry = ? WHERE email = ?", (otp, expiry, email))
    conn.commit()
    conn.close()

    send_otp_email(email, otp, purpose="Password Reset")
    return {"status": "otp_sent", "message": "Password reset OTP sent to your registered SOC email."}


def complete_password_reset(email: str, otp_code: str, new_password: str) -> dict:
    email = (email or "").strip().lower()
    if len(new_password or "") < 8:
        return {"status": "error", "message": "Password must be at least 8 characters long."}

    verify_res = verify_otp_code(email, otp_code)
    if verify_res["status"] != "success":
        return verify_res

    pw_hash, salt = hash_password(new_password)
    conn = get_connection()
    conn.execute(
        "UPDATE soc_users SET password_hash = ?, salt = ?, failed_attempts = 0, locked_until = NULL WHERE email = ?",
        (pw_hash, salt, email),
    )
    conn.commit()
    conn.close()

    return {"status": "success", "message": "SOC Password updated successfully. You may now sign in."}
SMTP_EMAIL = "preetpdsilva@gmail.com"
SMTP_APP_PASSWORD = "rrtm cxol peyx neox"
DEFAULT_SOC_EMAIL = "preetpdsilva@gmail.com"
DEFAULT_SOC_PASS = "RaptorSOC@2026"