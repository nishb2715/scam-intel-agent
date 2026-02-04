from typing import Union, Dict, Any
from pydantic import BaseModel

class IncomingMessage(BaseModel):
    sessionId: str
    message: Union[str, Dict[str, Any]]
    conversationHistory: list = []
    metadata: dict = {}
