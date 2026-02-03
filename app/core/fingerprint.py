# app/core/fingerprint.py

def generate_fingerprint():
    """
    Simple scam categorization
    """
    return {
        "scamType": "UPI_REFUND_FRAUD",
        "primaryTactics": ["urgency", "account_block_threat"],
        "paymentChannel": "UPI"
    }
