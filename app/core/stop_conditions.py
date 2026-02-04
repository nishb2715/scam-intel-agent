# app/core/stop_conditions.py

def should_trigger_callback(session):
    """
    Trigger callback once sufficient scam intelligence is collected.
    """

    intelligence = session.get("intelligence", {})

    has_upi = bool(intelligence.get("upiIds"))
    has_link = bool(intelligence.get("phishingLinks"))
    has_phone = bool(intelligence.get("phoneNumbers"))

    # Trigger if at least TWO strong scam artifacts are collected
    if sum([has_upi, has_link, has_phone]) >= 2:
        return True

    # OR if conversation is long enough
    if len(session.get("messages", [])) >= 5:
        return True

    return False
