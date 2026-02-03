# app/core/stop_conditions.py

def should_trigger_callback(session: dict) -> bool:
    """
    Determines whether final callback should be triggered.
    """

    has_upi = len(session["intelligence"]["upiIds"]) > 0
    has_link = len(session["intelligence"]["phishingLinks"]) > 0
    high_scam_score = session["scamScore"] >= 70
    probes_done = len(session["probesAsked"]) >= 3

    return has_upi or has_link or high_scam_score or probes_done
