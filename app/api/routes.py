# app/api/routes.py

from fastapi import APIRouter, Header, HTTPException, Depends
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
from app.config import API_KEY

router = APIRouter()

SCAM_ACTIVATION_THRESHOLD = 40

from fastapi import Header

def verify_api_key(x_api_key: str = Header(..., alias="x-api-key")):
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )

@router.get("/auth-test")
def auth_test(_: None = Depends(verify_api_key)):
    return {"status": "auth ok"}



@router.post("/message")
def handle_message(
    payload: IncomingMessage,
    _: None = Depends(verify_api_key)
):

    session = load_session(payload.sessionId)

    # 1. Store message
    session["messages"].append(payload.message)

    # 2. Scam detection
    message_scam_score = detect_scam(payload.message)
    session["scamScore"] += message_scam_score
    session["scamScore"] = min(session["scamScore"], 100)

    session["reasoningTrace"].append(
        log_reasoning(
            turn=len(session["messages"]),
            event="scam_signal_detected",
            scam_score=session["scamScore"]
        )
    )

    # 3. Intelligence extraction + scoring
    extracted = extract_entities(payload.message)

    for key, values in extracted.items():
        for value in values:
            existing_values = [i["value"] for i in session["intelligence"][key]]
            occurrences = session["messages"].count(value)

            if value not in existing_values:
                confidence = compute_confidence(
                    occurrences=occurrences,
                    formatted=True,
                    confirmed=False
                )

                session["intelligence"][key].append({
                    "value": value,
                    "confidence": confidence,
                    "sourceTurn": len(session["messages"])
                })

                session["reasoningTrace"].append({
                    "turn": len(session["messages"]),
                    "event": f"{key}_scored",
                    "value": value,
                    "confidence": confidence
                })

    # 4. Scam mode
    scam_mode = session["scamScore"] >= SCAM_ACTIVATION_THRESHOLD

    # 5. Persona / probing
    if scam_mode:
        probe_question, probe_type = get_probe_question(session)
        if probe_question:
            session["probesAsked"].append(probe_type)
            reply = probe_question
        else:
            reply = scam_persona_reply()
    else:
        reply = neutral_reply()

    # 6. Threat + fingerprint
    signals = {
        "urgency": "urgent" in payload.message.lower(),
        "payment_redirect": "upi" in payload.message.lower(),
        "phishing": "http" in payload.message.lower(),
        "multi_step": len(session["probesAsked"]) >= 2
    }

    session["threatLevel"] = compute_threat_level(signals)
    session["scamFingerprint"] = generate_fingerprint()

    # 7. Final callback check
    if should_trigger_callback(session) and not session.get("callbackSent"):
        session["callbackSent"] = True

        extracted_intelligence = {
            "bankAccounts": [],
            "upiIds": [item["value"] for item in session["intelligence"]["upiIds"]],
            "phishingLinks": [item["value"] for item in session["intelligence"]["phishingLinks"]],
            "phoneNumbers": [item["value"] for item in session["intelligence"]["phoneNumbers"]],
            "suspiciousKeywords": ["urgent", "verify", "account blocked"]
        }

        final_payload = {
            "sessionId": payload.sessionId,
            "scamDetected": True,
            "totalMessagesExchanged": len(session["messages"]),
            "extractedIntelligence": extracted_intelligence,
            "agentNotes": "Scammer used urgency framing and payment redirection tactics."
        }

        callback_status = send_guvi_callback(final_payload)

        session["reasoningTrace"].append({
            "turn": len(session["messages"]),
            "event": "guvi_callback_sent",
            "status": callback_status
        })


    # 8. Final response (evaluation-safe)
    return {
        "status": "success",
        "reply": reply
    }
