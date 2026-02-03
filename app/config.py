import os

API_KEY = os.environ.get("API_KEY")

print("🔑 Loaded API_KEY from env:", API_KEY)

if not API_KEY:
    raise RuntimeError("API_KEY is not set in environment variables")
