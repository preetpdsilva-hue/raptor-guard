"""
collector.py — Reads live local Windows Security Event logs via PowerShell.
"""

import subprocess
import json
from datetime import datetime

def read_windows_security_events(limit=10):
    """Fetches recent Windows Security events using PowerShell."""
    ps_script = f"""
    Get-WinEvent -LogName Security -MaxEvents {limit} | ForEach-Object {{
        [PSCustomObject]@{{
            Id = $_.Id
            Time = $_.TimeCreated.ToString("o")
            Message = $_.Message
            User = $_.Properties[5].Value
        }}
    }} | ConvertTo-Json -Compress
    """
    try:
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout.strip())
            if isinstance(data, dict):
                data = [data]
            
            events = []
            for item in data:
                events.append({
                    "timestamp": datetime.fromisoformat(item.get("Time")),
                    "event_id": item.get("Id", 0),
                    "source": "Windows Security Log",
                    "user": str(item.get("User", "SYSTEM")),
                    "host": "localhost",
                    "message": str(item.get("Message", ""))[:300].replace('\n', ' ')
                })
            return events
    except Exception as e:
        pass
    return []