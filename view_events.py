"""
view_events.py — Quick CLI to inspect stored events.
"""

import sys
from storage import get_recent

if __name__ == "__main__":
    classification = None
    limit = 50

    args = sys.argv[1:]
    for a in args:
        if a.upper() in ("SAFE", "SUSPICIOUS", "THREAT"):
            classification = a.upper()
        elif a.isdigit():
            limit = int(a)

    rows = get_recent(limit=limit, classification=classification)
    if not rows:
        print("No events found.")
    for r in rows:
        print(f"[{r['classification']}] {r['timestamp']} | {r['source']} | "
              f"EventID {r['event_id']} | user={r['user']} | {r['matched_reasons']}")
