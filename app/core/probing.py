# app/core/probing.py

def get_probe_question(session):
    """
    Decide the next probing question based on what we have already asked.
    """

    probes_asked = session.get("probesAsked", [])

    if "action" not in probes_asked:
        return "What exactly do I need to do now?", "action"

    if "destination" not in probes_asked:
        return "Where should I complete this verification?", "destination"

    if "payment" not in probes_asked:
        return "Can you share the link or UPI details again?", "payment"

    # Stop probing after predefined steps
    return None, None
