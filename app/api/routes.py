# app/api/routes.py

from fastapi import APIRouter, Header, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
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
# HELPER: Verify API Key
# -------------------------
def verify_api_key_from_request(request: Request) -> bool:
    """Check if request has valid API key"""
    api_key = request.headers.get("x-api-key")
    expected_key = os.environ.get("API_KEY")
    
    if not expected_key:
        return False
    
    return api_key == expected_key


# -------------------------
# CORE MESSAGE HANDLING LOGIC (EXTRACTED)
# -------------------------
def handle_message_logic(payload: IncomingMessage):
    """Core message handling logic - used by both / and /message endpoints"""
    try:
        session = load_session(payload.sessionId)
        session.setdefault("callbackSent", False)
        session.setdefault("probesAsked", [])
        session.setdefault("reasoningTrace", [])

        # Normalize message
        if isinstance(payload.message, dict):
            text = payload.message.get("text", "")
        elif isinstance(payload.message, str):
            text = payload.message
        else:
            text = str(payload.message)

        if not text:
            return {
                "status": "success",
                "reply": "I didn't catch that. Can you repeat?"
            }

        session["messages"].append(text)
        turn = len(session["messages"])

        # Scam detection
        score = detect_scam(text)
        session["scamScore"] = min(session["scamScore"] + score, 100)

        session["reasoningTrace"].append(
            log_reasoning(
                turn=turn,
                event="scam_signal_detected",
                scam_score=session["scamScore"]
            )
        )

        text_lower = text.lower()

        strong_signals = any([
            "upi" in text_lower,
            "http" in text_lower,
            "blocked" in text_lower,
            "suspended" in text_lower
        ])

        scam_mode = (
            session["scamScore"] >= SCAM_ACTIVATION_THRESHOLD
            or strong_signals
        )

        # Intelligence extraction
        extracted = extract_entities(text)

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

        # Persona / Probing
        if scam_mode:
            probe, probe_type = get_probe_question(session)
            if probe:
                session["probesAsked"].append(probe_type)
                reply = probe
            else:
                reply = scam_persona_reply()
        else:
            reply = neutral_reply()

        # Threat level
        signals = {
            "urgency": any(w in text_lower for w in ["urgent", "immediately", "today"]),
            "payment_redirect": "upi" in text_lower,
            "phishing": "http" in text_lower,
            "multi_step": len(session["probesAsked"]) >= 2
        }

        session["threatLevel"] = compute_threat_level(signals)

        # Scam fingerprint
        session["scamFingerprint"] = generate_fingerprint(session)

        # GUVI callback (non-blocking, only once)
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
                "agentNotes": (
                    "Autonomous agent used persona-driven probing "
                    "to extract structured scam intelligence."
                )
            })

        # Return response
        return {
            "status": "success",
            "reply": reply
        }
    
    except Exception as e:
        print(f"ERROR in handle_message_logic: {e}")
        import traceback
        traceback.print_exc()
        
        # Return safe fallback
        return {
            "status": "success",
            "reply": "I'm having trouble understanding. Can you explain again?"
        }


# -------------------------
# ROOT ENDPOINT (HANDLES BOTH GET AND POST)
# -------------------------
@router.api_route("/", methods=["GET", "POST", "HEAD"])
async def root_endpoint(request: Request):
    """
    GET/HEAD: Health check
    POST: Message handling (for evaluation compatibility)
    """
    
    # Health check for GET/HEAD
    if request.method in ["GET", "HEAD"]:
        return {
            "status": "success",
            "reply": "Agentic honeypot API is live"
        }
    
    # POST: Handle as message request
    try:
        # Verify API key
        if not verify_api_key_from_request(request):
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing API key"}
            )
        
        # Parse request body
        body = await request.json()
        
        # Check if it's a message request
        if "sessionId" in body and "message" in body:
            payload = IncomingMessage(**body)
            return handle_message_logic(payload)
        
        # Not a message request
        return {
            "status": "success",
            "reply": "Invalid request format"
        }
    
    except Exception as e:
        print(f"Root endpoint error: {e}")
        import traceback
        traceback.print_exc()
        
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "reply": "I'm having trouble processing that. Can you try again?"
            }
        )


# -------------------------
# /message ENDPOINT (EXPLICIT PATH)
# -------------------------
def verify_api_key(x_api_key: str = Header(..., alias="x-api-key")):
    """API key dependency for /message endpoint"""
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


@router.post("/message")
def handle_message(
    payload: IncomingMessage,
    _: None = Depends(verify_api_key)
):
    """Dedicated /message endpoint"""
    return handle_message_logic(payload)


# -------------------------
# AUTH TEST (OPTIONAL)
# -------------------------
@router.get("/auth-test")
def auth_test(_: None = Depends(verify_api_key)):
    return {"status": "auth ok"}