# app/core/intelligence.py

def compute_confidence(
    occurrences: int,
    formatted: bool = True,
    confirmed: bool = False
) -> float:
    """
    Confidence scoring logic (simple & explainable)
    """
    score = 0.6

    if occurrences > 1:
        score += 0.2

    if formatted:
        score += 0.1

    if confirmed:
        score += 0.1

    return min(score, 1.0)
