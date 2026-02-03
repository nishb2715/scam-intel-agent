# app/core/persona.py

def neutral_reply():
    return "Thanks for the message. How can I help you?"

def scam_persona_reply():
    """
    Confused but cooperative persona.
    """
    return (
        "Sorry, I’m a bit confused. "
        "I received some messages earlier. "
        "Can you explain what I need to do?"
    )
