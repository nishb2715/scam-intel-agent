# app/core/extraction.py

import re

UPI_REGEX = r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}"
URL_REGEX = r"https?://[^\s]+"
PHONE_REGEX = r"\+?\d{10,13}"

def extract_entities(message: str):
    """
    Extracts raw intelligence entities from a message.
    """

    upi_ids = re.findall(UPI_REGEX, message)
    urls = re.findall(URL_REGEX, message)
    phones = re.findall(PHONE_REGEX, message)

    return {
        "upiIds": upi_ids,
        "phishingLinks": urls,
        "phoneNumbers": phones
    }
