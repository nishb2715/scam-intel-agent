# app/core/persona.py

import random

def neutral_reply():
    """Reply for non-scam messages"""
    return "Thanks for the message. How can I help you?"

def scam_persona_reply():
    """
    Confused but cooperative persona with varied responses.
    Prevents repetitive loops.
    """
    responses = [
        "I want to fix this urgently. What exactly do you need from me?",
        "Okay, I'm ready to help. Can you walk me through the steps?",
        "I understand it's serious. What information should I provide?",
        "Alright, I'll cooperate. Just tell me what to send.",
        "I'm a bit worried now. What do I need to do to resolve this?",
        "Got it. How exactly should I proceed with this?",
        "I'm willing to help. What details do you need from me?"
    ]
    return random.choice(responses)