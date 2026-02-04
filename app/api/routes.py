from fastapi import APIRouter, Header, HTTPException, Depends
import os

from app.models.schemas import IncomingMessage
from app.core.session import load_session
from app.core.detection import detect_scam
from app.core.reasoning import log_reasoning
from app.core.persona import neutral_reply, scam_persona_reply
from app.core.probing import get_probe_question
from app.core.extraction import extract_entities
from app.core.intelligence import compute_confidence
from app.core.threat import compute_threat_level
from app.core.fingerprint import generate_fingerprint
from app.core.stop_conditions import should_trigger_callback
from app.services.guvi_callback import send_guvi_callback

router = APIRouter()

SCAM_ACTIVATION_THRESHOLD = 20


# -------------------------
# API KEY AUTH (ONLY FOR REAL ENDPOINTS)
# -------------------------
def verify_api_key(x_api_key: str = Header(..., alias="x-api-key")):
    expected_key = os.environ.get("API_KEY")

    if not expected_key:
        raise HTTPException(
            status_code=500,
            detail="Server misconfiguration: API key not set"
        )

    if x_api_key != expected_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )


# -------------------------
# ROOT HEALTH CHECK (NO AUTH)
# -------------------------
@router.get("/")
@router.head("/")
@router.post("/")
def root_health_check(_: Request):
    return {
        "status": "ok",
        "message": "Agentic honeypot API is live"
    }


# -------------------------
# AUTH TEST (DEBUG ONLY)
# -------------------------
@router.get("/auth-test")
def auth_test(_: None = Depends(verify_api_key)):
    return {"status": "auth ok"}


# -------------------------
# MAIN MESSAGE HANDLER
# -------------------------
@router.post("/message")
def handle_message(
    payload: IncomingMessage,
    _: None = Depends(verify_api_key)
):
    session = load_session(payload.sessionId)

    session.setdefault("callbackSent", False)
    session.setdefault("probesAsked", [])
    session.setdefault("reasoningTrace", [])

    # 1. Message tracking
    session["messages"].append(payload.message)
    turn = len(session["messages"])

    # 2. Scam detection
    score = detect_scam(payload.message)
    session["scamScore"] = min(session["scamScore"] + score, 100)

    session["reasoningTrace"].append(
        log_reasoning(
            turn=turn,
            event="scam_signal_detected",
            scam_score=session["scamScore"]
        )
    )

    strong_signals = any([
        "upi" in payload.message.lower(),
        "http" in payload.message.lower(),
        "blocked" in payload.message.lower(),
        "suspended" in payload.message.lower()
    ])

    scam_mode = session["scamScore"] >= SCAM_ACTIVATION_THRESHOLD or strong_signals

    # 3. Intelligence extraction
    extracted = extract_entities(payload.message)

    for key, values in extracted.items():
        for value in values:
            existing = [i["value"] for i in session["intelligence"][key]]
            if value not in existing:
                confidence = compute_confidence(
                    occurrences=session["messages"].count(value),
                    formatted=True,
                    confirmed=False
                )
                session["intelligence"][key].append({
                    "value": value,
                    "confidence": confidence,
                    "sourceTurn": turn
                })

    # 4. Persona + probing
    if scam_mode:
        probe, probe_type = get_probe_question(session)
        if probe:
            session["probesAsked"].append(probe_type)
            reply = probe
        else:
            reply = scam_persona_reply()
    else:
        reply = neutral_reply()

    # 5. Threat scoring
    signals = {
        "urgency": any(w in payload.message.lower() for w in ["urgent", "immediately", "today"]),
        "payment_redirect": "upi" in payload.message.lower(),
        "phishing": "http" in payload.message.lower(),
        "multi_step": len(session["probesAsked"]) >= 2
    }

    session["threatLevel"] = compute_threat_level(signals)

    # 6. Fingerprint
    session["scamFingerprint"] = generate_fingerprint(session)

    # 7. GUVI callback
    if should_trigger_callback(session) and not session["callbackSent"]:
        session["callbackSent"] = True

        send_guvi_callback({
            "sessionId": payload.sessionId,
            "scamDetected": True,
            "totalMessagesExchanged": turn,
            "threatLevel": session["threatLevel"],
            "scamFingerprint": session["scamFingerprint"],
            "extractedIntelligence": session["intelligence"],
            "reasoningTrace": session["reasoningTrace"],
            "agentNotes": "Persona-driven engagement with structured intelligence extraction."
        })

    return {
        "status": "success",
        "reply": reply
    }
