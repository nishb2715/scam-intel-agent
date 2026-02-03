# app/core/detection.py

SCAM_KEYWORDS = {
    "urgent": 15,
    "verify": 15,
    "account blocked": 20,
    "refund": 15,
    "upi": 20,
    "click": 10,
    "link": 10
}

def detect_scam(message: str) -> int:
    """
    Returns a scam score for a single message.
    """
    score = 0
    message_lower = message.lower()

    for keyword, weight in SCAM_KEYWORDS.items():
        if keyword in message_lower:
            score += weight

    # cap per-message contribution
    return min(score, 50)
