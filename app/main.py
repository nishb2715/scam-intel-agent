from fastapi import FastAPI
from app.api.routes import router

app = FastAPI(title="Scam Intelligence Agent")

app.include_router(router)
