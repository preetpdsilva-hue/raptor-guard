"""
storage.py — Thread-safe SQLite storage engine for Raptor Guard.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "events.db"


def get_connection():
    """Returns a SQLite connection with a 10-second busy timeout."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL;")  # Enable WAL mode for high concurrency
    return conn


def format_24h_local(ts):
    """Converts datetime objects or ISO strings to local 24-hour format (YYYY-MM-DD HH:MM:SS)."""
    if not ts:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(ts, datetime):
        if ts.tzinfo is not None:
            ts = ts.astimezone()  # Shift to local IST timezone
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    
    ts_str = str(ts).strip()
    try:
        # Handle ISO strings with 'T', 'Z', or timezone offsets
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        # Fallback: strip 'T' and milliseconds if already close to standard format
        return ts_str.replace("T", " ")[:19]


def init_db():
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_id INTEGER,
            source TEXT,
            user TEXT,
            host TEXT,
            message TEXT,
            classification TEXT,
            matched_reasons TEXT
        )
        """
    )

    columns = [
        ("response_status", "TEXT DEFAULT 'Open'"),
        ("analyst_notes", "TEXT DEFAULT ''"),
        ("pid", "INTEGER DEFAULT 0"),
        ("process_name", "TEXT DEFAULT ''"),
        ("level", "INTEGER DEFAULT 3"),
        ("mitre_tactic", "TEXT DEFAULT 'Discovery'"),
        ("mitre_technique", "TEXT DEFAULT 'T1083'"),
        ("agent_os", "TEXT DEFAULT 'Windows'"),
    ]

    for col, definition in columns:
        try:
            conn.execute(f"ALTER TABLE events ADD COLUMN {col} {definition}")
        except sqlite3.OperationalError:
            pass  # Column already exists

    conn.execute("CREATE TABLE IF NOT EXISTS targets (host TEXT UNIQUE)")
    conn.execute("INSERT OR IGNORE INTO targets (host) VALUES ('127.0.0.1')")

    # Automatically clean up any existing ISO 'T' timestamps in the database
    conn.execute(
        """
        UPDATE events 
        SET timestamp = replace(substr(timestamp, 1, 19), 'T', ' ') 
        WHERE timestamp LIKE '%T%'
        """
    )

    conn.commit()
    conn.close()


def get_targets():
    conn = get_connection()
    cur = conn.execute("SELECT host FROM targets")
    hosts = [r[0] for r in cur.fetchall()]
    conn.close()
    return hosts


def add_target(host):
    if host:
        conn = get_connection()
        conn.execute("INSERT OR IGNORE INTO targets (host) VALUES (?)", (host,))
        conn.commit()
        conn.close()


def save_event(event):
    conn = get_connection()
    ts_str = format_24h_local(event.get("timestamp"))

    conn.execute(
        """
        INSERT INTO events (
            timestamp, event_id, source, user, host, message, 
            classification, matched_reasons, pid, process_name, 
            level, mitre_tactic, mitre_technique, agent_os
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ts_str,
            event["event_id"],
            event.get("source", ""),
            event.get("user", ""),
            event.get("host", ""),
            event.get("message", "")[:1000],
            event["classification"],
            json.dumps(event.get("matched_reasons", [])),
            event.get("pid", 0),
            event.get("process_name", ""),
            event.get("level", 3),
            event.get("mitre_tactic", "Discovery"),
            event.get("mitre_technique", "T1083"),
            event.get("agent_os", "Windows"),
        ),
    )
    conn.commit()
    conn.close()


def get_recent(limit=100, host_filter=None):
    conn = get_connection()
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM events WHERE 1=1"
    params = []

    if host_filter:
        query += " AND host = ?"
        params.append(host_filter)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cur = conn.execute(query, params)
    rows = []
    for r in cur.fetchall():
        d = dict(r)
        d["timestamp"] = format_24h_local(d.get("timestamp"))
        rows.append(d)
    conn.close()
    return rows


def update_event_status(event_id, status, notes):
    conn = get_connection()
    conn.execute(
        "UPDATE events SET response_status = ?, analyst_notes = ? WHERE id = ?",
        (status, notes, event_id),
    )
    conn.commit()
    conn.close()