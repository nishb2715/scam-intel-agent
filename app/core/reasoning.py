# app/core/reasoning.py

def log_reasoning(turn: int, event: str, scam_score: int):
    """
    Creates a reasoning trace entry.
    """
    return {
        "turn": turn,
        "event": event,
        "scamScore": scam_score
    }
