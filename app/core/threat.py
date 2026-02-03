# app/core/threat.py

def compute_threat_level(signals: dict) -> int:
    """
    Computes threat level (1–10)
    """
    score = 0

    if signals.get("urgency"):
        score += 2
    if signals.get("payment_redirect"):
        score += 3
    if signals.get("phishing"):
        score += 3
    if signals.get("multi_step"):
        score += 2

    return min(score, 10)
