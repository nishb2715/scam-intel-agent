# app/services/guvi_callback.py

import requests

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def send_guvi_callback(payload: dict):
    """
    Sends final extracted intelligence to GUVI evaluation endpoint.
    """
    try:
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=5
        )
        return response.status_code
    except Exception as e:
        return str(e)
