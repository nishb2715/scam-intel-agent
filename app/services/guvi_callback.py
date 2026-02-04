# app/services/guvi_callback.py

import requests

GUVI_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def send_guvi_callback(payload):
    print(f"[GUVI] Sending callback for session: {payload.get('sessionId')}")

    try:
        response = requests.post(
            GUVI_ENDPOINT,
            json=payload,
            timeout=5
        )

        print(f"[GUVI] Callback status: {response.status_code}")
        print(f"[GUVI] Callback response: {response.text}")

        return response.status_code

    except Exception as e:
        print(f"[GUVI] Callback FAILED: {str(e)}")
        return None
