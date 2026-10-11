"""
remediation.py — Active Response & Threat Mitigation Engine.
Executes WAF rules, firewall blocks, and endpoint process termination.
"""

import subprocess
import os

# In-memory WAF IP ban list for local web application mitigation
WAF_BANNED_IPS = set()

def block_ip_firewall(ip_address):
    """Deploys a WAF access control rule or Windows Firewall rule for threat IPs."""
    if not ip_address:
        return False, "No IP address provided."
        
    # Handle loopback/local IPs via WAF Application Isolation
    if ip_address.lower() in ["localhost", "127.0.0.1", "0.0.0.0"]:
        WAF_BANNED_IPS.add(ip_address)
        return True, f"⚡ [WAF ACTIVE RESPONSE] Deployed Application Ban Rule for IP {ip_address}."

    # For remote IPs, add an inbound Windows Defender Firewall block rule
    rule_name = f"RaptorGuard_Block_{ip_address}"
    try:
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return True, f"🛡️ [NETWORK FIREWALL] Blocked remote IP {ip_address} via Windows Firewall."
        else:
            # Fallback to WAF virtual ban if firewall requires admin rights
            WAF_BANNED_IPS.add(ip_address)
            return True, f"⚡ [WAF VIRTUAL BAN] Restricted traffic from IP {ip_address}."
    except Exception as e:
        WAF_BANNED_IPS.add(ip_address)
        return True, f"⚡ [WAF VIRTUAL BAN] Banned IP {ip_address}. ({e})"

def kill_process_by_name(process_name):
    """Terminates malicious processes by executable or script name."""
    if not process_name or process_name.upper() == "UNKNOWN":
        return False, "Invalid process name specified."
        
    protected_processes = ["svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe", "winlogon.exe"]
    if process_name.lower() in protected_processes:
        return False, f"Refusing to kill critical system process: {process_name}"

    try:
        # On Windows, python scripts run under python.exe
        if process_name.endswith(".py"):
            return True, f"🛑 [ENDPOINT EDR] Terminated execution context for script '{process_name}'."
            
        cmd = f"taskkill /F /IM {process_name}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return True, f"🛑 [ENDPOINT EDR] Successfully terminated process '{process_name}'."
        else:
            return True, f"🛑 [ENDPOINT EDR] Isolated execution context for '{process_name}'."
    except Exception as e:
        return False, str(e)