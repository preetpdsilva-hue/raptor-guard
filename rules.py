"""
rules.py — Host-Based SIEM Detection Rules (Windows Event Logs & Linux Syslog).
Classifies OS telemetry into High/Critical Threats vs. Low/Safe Events.
"""

from collections import defaultdict
from datetime import datetime, timedelta

_failed_login_history = defaultdict(list)
FAILED_LOGIN_THRESHOLD = 4
FAILED_LOGIN_WINDOW_MIN = 3


def rule_os_brute_force(event):
    """Detects brute force attacks (Windows 4625 / Linux failed logins)."""
    if event.get("event_id") != 4625:
        return None

    ip = event.get("host", "UNKNOWN")
    user = event.get("user", "UNKNOWN")
    now = datetime.now()
    
    tracker_key = f"{ip}_{user}"
    history = _failed_login_history[tracker_key]
    history.append(now)

    cutoff = now - timedelta(minutes=FAILED_LOGIN_WINDOW_MIN)
    _failed_login_history[tracker_key] = [t for t in history if t >= cutoff]

    count = len(_failed_login_history[tracker_key])
    if count >= FAILED_LOGIN_THRESHOLD:
        return {
            "severity": "THREAT",
            "level": 13,
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110.001",
            "reason": f"CRITICAL: OS Brute Force detected! {count} failed logins for user '{user}'.",
        }
    else:
        return {
            "severity": "SUSPICIOUS",
            "level": 6,
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110",
            "reason": f"HIGH: Multiple failed login attempts ({count}) for user '{user}'.",
        }


def rule_suspicious_execution(event):
    """Detects execution of reconnaissance tools or suspicious commands."""
    msg = str(event.get("message", "")).lower()
    
    critical_cmds = ["vssadmin delete shadows", "mimikatz", "powershell -enc", "wget http", "curl -o /tmp/"]
    for cmd in critical_cmds:
        if cmd in msg:
            return {
                "severity": "THREAT",
                "level": 14,
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "T1059",
                "reason": f"CRITICAL: Highly malicious command execution detected: '{cmd}'.",
            }

    suspicious_cmds = ["whoami", "net user /add", "useradd", "chmod 777", "taskkill", "net localgroup administrators"]
    for cmd in suspicious_cmds:
        if cmd in msg:
            return {
                "severity": "SUSPICIOUS",
                "level": 8,
                "mitre_tactic": "Discovery",
                "mitre_technique": "T1087",
                "reason": f"HIGH: Suspicious command execution detected: '{cmd}'.",
            }
    return None


def rule_privilege_escalation(event):
    """Detects administrative privilege escalation (Windows 4672 / Linux sudo)."""
    if event.get("event_id") == 4672 or "sudo" in str(event.get("source", "")).lower():
        user = event.get("user", "root")
        return {
            "severity": "SUSPICIOUS",
            "level": 7,
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1078.003",
            "reason": f"HIGH: Privileged Administrator execution (sudo/admin logon) by '{user}'.",
        }
    return None


def rule_account_created(event):
    """Detects new local account creation (Windows 4720 / Linux useradd)."""
    if event.get("event_id") == 4720:
        return {
            "severity": "THREAT",
            "level": 11,
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1136",
            "reason": f"CRITICAL: New local user account was created on the system.",
        }
    return None


def rule_normal_logon(event):
    """Normal baseline event (Windows 4624 / Linux session opened)."""
    if event.get("event_id") == 4624:
        return {
            "severity": "SAFE",
            "level": 3,
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1078",
            "reason": f"LOW / NORMAL: Successful user logon for '{event.get('user', 'User')}'.",
        }
    return None


RULES = [
    rule_os_brute_force,
    rule_suspicious_execution,
    rule_privilege_escalation,
    rule_account_created,
    rule_normal_logon,
]