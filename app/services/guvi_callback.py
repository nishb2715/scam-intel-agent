# app/services/guvi_callback.py

import requests
import threading

GUVI_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def send_guvi_callback(payload):
    """Send GUVI callback in background thread (non-blocking)"""
    
    def _send_in_background():
        try:
            print(f"[GUVI] Sending callback for session: {payload.get('sessionId')}")
            
            response = requests.post(
                GUVI_ENDPOINT,
                json=payload,
                timeout=3  # Reduced timeout
            )
            
            print(f"[GUVI] Callback status: {response.status_code}")
            print(f"[GUVI] Callback response: {response.text}")
            
        except requests.exceptions.Timeout:
            print(f"[GUVI] Callback timed out (non-critical)")
        except requests.exceptions.RequestException as e:
            print(f"[GUVI] Callback failed (non-critical): {e}")
        except Exception as e:
            print(f"[GUVI] Unexpected callback error: {e}")
    
    # Start background thread (daemon=True means it won't block shutdown)
    thread = threading.Thread(target=_send_in_background, daemon=True)
    thread.start()
    
    print(f"[GUVI] Callback thread started (non-blocking)")