from typing import Dict, Any

# In-memory session store
SESSION_STORE: Dict[str, Dict[str, Any]] = {}

def load_session(session_id: str) -> Dict[str, Any]:
    """
    Loads an existing session or creates a new one.
    """
    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {
            "messages": [],
            "scamScore": 0,
            "intelligence": {
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": []
            },
            "threatLevel": 0,
            "scamFingerprint": {},   # ✅ COMMA WAS MISSING HERE
            "reasoningTrace": [],
            "probesAsked": [],
            "callbackSent": False
        }

    return SESSION_STORE[session_id]
