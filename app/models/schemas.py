from pydantic import BaseModel

class IncomingMessage(BaseModel):
    sessionId: str
    message: str
