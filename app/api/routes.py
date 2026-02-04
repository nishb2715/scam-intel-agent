# app/api/routes.py

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
# API KEY AUTH
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

    # 🔒 GUARANTEE REQUIRED FIELDS (CRITICAL)
    session.setdefault("callbackSent", False)
    session.setdefault("probesAsked", [])
    session.setdefault("reasoningTrace", [])

    # -----------------------------------
    # 1. TURN & MESSAGE TRACKING
    # -----------------------------------
    session["messages"].append(payload.message)
    turn = len(session["messages"])

    # -----------------------------------
    # 2. SCAM DETECTION
    # -----------------------------------
    message_scam_score = detect_scam(payload.message)
    session["scamScore"] += message_scam_score
    session["scamScore"] = min(session["scamScore"], 100)

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

    scam_mode = (
        session["scamScore"] >= SCAM_ACTIVATION_THRESHOLD
        or strong_signals
    )


    # -----------------------------------
    # 3. INTELLIGENCE EXTRACTION
    # -----------------------------------
    extracted = extract_entities(payload.message)

    for key, values in extracted.items():
        for value in values:
            existing = [i["value"] for i in session["intelligence"][key]]
            occurrences = session["messages"].count(value)

            if value not in existing:
                confidence = compute_confidence(
                    occurrences=occurrences,
                    formatted=True,
                    confirmed=False
                )

                session["intelligence"][key].append({
                    "value": value,
                    "confidence": confidence,
                    "sourceTurn": turn
                })

                session["reasoningTrace"].append({
                    "turn": turn,
                    "event": "intelligence_extracted",
                    "type": key,
                    "value": value,
                    "confidence": confidence
                })

    # -----------------------------------
    # 4. STRATEGIC PROBING / PERSONA
    # -----------------------------------
    if scam_mode:
        probe_question, probe_type = get_probe_question(session)

        if probe_question:
            session["probesAsked"].append(probe_type)
            reply = probe_question
        else:
            reply = scam_persona_reply()
    else:
        reply = neutral_reply()

    # -----------------------------------
    # 5. THREAT LEVEL SCORING
    # -----------------------------------
    signals = {
        "urgency": any(w in payload.message.lower() for w in ["urgent", "immediately", "today"]),
        "payment_redirect": "upi" in payload.message.lower(),
        "phishing": "http" in payload.message.lower(),
        "multi_step": len(session["probesAsked"]) >= 2
    }

    session["threatLevel"] = compute_threat_level(signals)

    session["reasoningTrace"].append({
        "turn": turn,
        "event": "threat_level_updated",
        "threatLevel": session["threatLevel"],
        "scamScore": session["scamScore"]
    })

    # -----------------------------------
    # 6. SCAM FINGERPRINTING
    # -----------------------------------
    session["scamFingerprint"] = generate_fingerprint(session)


    session["reasoningTrace"].append({
        "turn": turn,
        "event": "scam_fingerprint_generated",
        "fingerprint": session["scamFingerprint"]
    })

    # -----------------------------------
    # 7. FINAL GUVI CALLBACK (ONCE)
    # -----------------------------------
    if should_trigger_callback(session) and not session.get("callbackSent"):

        session["callbackSent"] = True

        final_payload = {
            "sessionId": payload.sessionId,
            "scamDetected": True,
            "totalMessagesExchanged": turn,
            "threatLevel": session["threatLevel"],
            "scamFingerprint": session["scamFingerprint"],
            "extractedIntelligence": session["intelligence"],
            "reasoningTrace": session["reasoningTrace"],
            "agentNotes": (
                "Agent autonomously engaged scammer using persona-driven probing, "
                "extracted structured intelligence, and assessed threat severity."
            )
        }

        callback_status = send_guvi_callback(final_payload)

        session["reasoningTrace"].append({
            "turn": turn,
            "event": "guvi_callback_sent",
            "status": callback_status
        })

    # -----------------------------------
    # 8. FINAL RESPONSE
    # -----------------------------------
    return {
        "status": "success",
        "reply": reply
    }
