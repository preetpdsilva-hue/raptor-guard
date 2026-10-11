"""
main.py — Entry point. Polls Windows Event Log, classifies events, stores
and alerts on results.

Run as Administrator (required to read the Security log):
    python main.py
"""

import time
import sys
from datetime import datetime

from collector import poll_all_channels, prime_baseline
from classifier import classify_event
from storage import init_db, save_event

POLL_INTERVAL_SECONDS = 10

COLOR = {
    "THREAT": "[91m",       # red
    "SUSPICIOUS": "[93m",   # yellow
    "SAFE": "[92m",         # green
    "RESET": "[0m",
}


def print_event(event):
    c = COLOR.get(event["classification"], "")
    r = COLOR["RESET"]
    print(f"{c}[{event['classification']}]{r} {event['timestamp']} | "
          f"{event['source']} | EventID {event['event_id']} | user={event['user']}")
    for reason in event.get("matched_reasons", []):
        print(f"    -> {reason}")


def main():
    print("Initializing database...")
    init_db()

    print("Priming baseline (ignoring historical events)...")
    prime_baseline()

    print(f"Monitoring started. Polling every {POLL_INTERVAL_SECONDS}s. Ctrl+C to stop.\n")

    try:
        while True:
            events = poll_all_channels()
            for event in events:
                classified = classify_event(event)
                save_event(classified)
                if classified["classification"] != "SAFE":
                    print_event(classified)
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
