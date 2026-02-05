# app/core/extraction.py

import re

# Updated patterns
UPI_REGEX = r"\b[\w\.-]+@[a-zA-Z]+\b"  # More flexible - matches any domain
URL_REGEX = r"https?://[^\s;,]+"  # Excludes punctuation at end
PHONE_REGEX = r"(?:\+91[-\s]?)?(\d{10})"  # Matches with or without +91

def extract_entities(message: str):
    """
    Extracts raw intelligence entities from a message.
    Returns normalized, deduplicated values.
    """
    
    # Extract UPI IDs
    upi_ids = re.findall(UPI_REGEX, message)
    upi_ids = list(set(upi_ids))  # Deduplicate
    
    # Extract URLs
    urls = re.findall(URL_REGEX, message)
    # Clean trailing punctuation
    urls = [url.rstrip(';.,') for url in urls]
    urls = list(set(urls))  # Deduplicate
    
    # Extract phone numbers
    phone_matches = re.findall(PHONE_REGEX, message)
    # Normalize to +91-XXXXXXXXXX format
    phones = []
    for phone in phone_matches:
        normalized = f"+91-{phone}"
        if normalized not in phones:
            phones.append(normalized)
    
    return {
        "upiIds": upi_ids,
        "phishingLinks": urls,
        "phoneNumbers": phones
    }