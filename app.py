from flask import Flask, jsonify, send_file, request
import json
import threading
import time
from datetime import datetime
from storage import get_recent, update_event_status, add_target, save_event, get_targets, init_db
from classifier import classify_event
from remediation import kill_process_by_name, block_ip_firewall
from collector import read_windows_security_events

app = Flask(__name__)
init_db()

# === BACKGROUND WORKER: Local Windows Event Ingestion ===
def windows_collector_thread():
    """Polls local Windows Security event logs periodically."""
    seen_ids = set()
    while True:
        try:
            events = read_windows_security_events(limit=5)
            for ev in events:
                event_hash = f"{ev['timestamp']}_{ev['event_id']}_{ev['user']}"
                if event_hash not in seen_ids:
                    seen_ids.add(event_hash)
                    classified = classify_event(ev)
                    save_event(classified)
                    add_target("127.0.0.1") # Standardize local Windows IP
            if len(seen_ids) > 1000:
                seen_ids.clear()
        except Exception:
            pass
        time.sleep(4)

collector_daemon = threading.Thread(target=windows_collector_thread, daemon=True)
collector_daemon.start()


@app.route('/')
def index():
    return send_file('raptor-guard-dashboard.html')


@app.route('/api/hosts')
def api_hosts():
    return jsonify(get_targets())


@app.route('/api/logs')
def api_logs():
    target_host = request.args.get('host', 'all')
    
    # If 'all' is selected, pass None to the database filter to merge all OS logs
    filter_val = None if target_host == 'all' else target_host
    rows = get_recent(limit=150, host_filter=filter_val)

    formatted_logs = []
    for r in rows:
        reasons = json.loads(r["matched_reasons"]) if r["matched_reasons"] else []
        threat_type = reasons[0] if reasons else f"Event ID {r['event_id']}"

        formatted_logs.append({
            "id": r["id"],
            "time": r["timestamp"],
            "severity": r["classification"],
            "type": threat_type,
            "ip": r["host"] if r["host"] else "Unknown IP",
            "target": r["user"] if r["user"] else "SYSTEM",
            "response_status": r.get("response_status", "Open"),
            "analyst_notes": r.get("analyst_notes", ""),
            "message": r.get("message", ""),
            "process_name": r.get("process_name", "system"),
            "level": r.get("level", 3),
            "mitre_tactic": r.get("mitre_tactic", "Discovery"),
            "mitre_technique": r.get("mitre_technique", "None"),
            "agent_os": r.get("agent_os", "Windows")
        })
    return jsonify(formatted_logs)


@app.route('/api/logs/<int:log_id>/status', methods=['POST'])
def update_status(log_id):
    data = request.json or {}
    status = data.get('status', 'Open')
    notes = data.get('notes', '')
    update_event_status(log_id, status, notes)
    return jsonify({"success": True, "id": log_id, "status": status, "notes": notes})


@app.route('/api/remediate', methods=['POST'])
def active_response():
    data = request.json or {}
    action_type = data.get("action")
    target_val = data.get("target")
    log_id = data.get("log_id")
    final_status = data.get("status", "Remediated")

    success = False
    message = "Unknown Action"

    if action_type == "kill_name":
        success, message = kill_process_by_name(target_val)
    elif action_type == "block_ip":
        success, message = block_ip_firewall(target_val)

    if success and log_id:
        update_event_status(log_id, final_status, message)

    return jsonify({"success": success, "message": message})


@app.route('/api/targets', methods=['POST'])
def add_new_target():
    data = request.json or {}
    host = data.get('host')
    if host:
        add_target(host)
        return jsonify({"success": True, "host": host})
    return jsonify({"success": False}), 400


@app.route('/api/ingest', methods=['POST'])
def ingest_agent_logs():
    data = request.json or {}
    event = {
        "timestamp": datetime.now(),
        "event_id": data.get("event_id", 0),
        "source": data.get("source", "Linux Syslog"),
        "user": data.get("user", "root"),
        "host": data.get("host", request.remote_addr),
        "message": data.get("message", ""),
        "process_name": data.get("process_name", "sshd"),
        "agent_os": data.get("agent_os", "Linux")
    }

    classified = classify_event(event)

    # Fallbacks if rules don't catch it
    if "level" not in classified:
        classified["level"] = 3 if event["event_id"] == 4624 else 8
    if "mitre_tactic" not in classified:
        classified["mitre_tactic"] = "Initial Access"
    if "mitre_technique" not in classified:
        classified["mitre_technique"] = "T1078"

    save_event(classified)
    add_target(event["host"])

    return jsonify({"success": True})


if __name__ == '__main__':
    print("Starting Global SIEM Server on http://0.0.0.0:5000 ...")
    app.run(host='0.0.0.0', port=5000, debug=True)