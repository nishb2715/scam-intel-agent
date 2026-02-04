# app/core/fingerprint.py

def generate_fingerprint(session):
    """
    Generate a normalized scam fingerprint based on session intelligence
    """

    intelligence = session.get("intelligence", {})
    threat_level = session.get("threatLevel", 0)
    probes = session.get("probesAsked", [])

    scam_type = "UNKNOWN"

    if intelligence.get("upiIds"):
        scam_type = "UPI_REFUND_FRAUD"
    elif intelligence.get("phishingLinks"):
        scam_type = "PHISHING_SCAM"
    elif intelligence.get("phoneNumbers"):
        scam_type = "CALL_BASED_SCAM"

    primary_tactics = []

    if threat_level >= 7:
        primary_tactics.append("urgency")

    if intelligence.get("upiIds"):
        primary_tactics.append("payment_redirection")

    if intelligence.get("phishingLinks"):
        primary_tactics.append("phishing_link")

    if len(probes) >= 2:
        primary_tactics.append("multi_step_manipulation")

    return {
        "scamType": scam_type,
        "primaryTactics": primary_tactics,
        "paymentChannel": "UPI" if intelligence.get("upiIds") else "UNKNOWN",
        "linkUsed": bool(intelligence.get("phishingLinks"))
    }
