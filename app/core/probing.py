# app/core/probing.py

def get_probe_question(session):
    intelligence = session.get("intelligence", {})
    asked = set(session.get("probesAsked", []))

    # 1. Extract UPI
    if not intelligence.get("upiIds") and "upi" not in asked:
        return (
            "I’m not very familiar with UPI. Can you tell me exactly what ID I should use?",
            "upi"
        )

    # 2. Extract phishing link
    if not intelligence.get("phishingLinks") and "link" not in asked:
        return (
            "I tried opening the link but it’s not working. Can you send it again?",
            "link"
        )

    # 3. Extract phone number
    if not intelligence.get("phoneNumbers") and "phone" not in asked:
        return (
            "Should I call someone to resolve this? What number do I call?",
            "phone"
        )

    # Nothing left to probe
    return (None, None)
