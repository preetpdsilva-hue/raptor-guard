"""
classifier.py — Runs a normalized event through all detection rules and
assigns a final classification, alert level, and MITRE metadata.
"""

from rules import RULES

SEVERITY_RANK = {"SAFE": 0, "SUSPICIOUS": 1, "THREAT": 2}


def classify_event(event):
    best_severity = "SAFE"
    reasons = []
    highest_rank = -1

    for rule_fn in RULES:
        result = rule_fn(event)
        if result:
            reasons.append(result["reason"])
            rank = SEVERITY_RANK.get(result["severity"], 0)
            
            # Update event with rule attributes if it's the highest severity match
            if rank >= highest_rank:
                highest_rank = rank
                best_severity = result["severity"]
                
                if "level" in result:
                    event["level"] = result["level"]
                if "mitre_tactic" in result:
                    event["mitre_tactic"] = result["mitre_tactic"]
                if "mitre_technique" in result:
                    event["mitre_technique"] = result["mitre_technique"]

    event["classification"] = best_severity
    event["matched_reasons"] = reasons
    return event