from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class ProcessedEvent(BaseModel):
    timestamp: datetime
    source_ip: str
    source_port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    event_type: str
    session_id: str
    message: Optional[str] = None
    risk_score: int = Field(..., ge=0, le=100)
    risk_factors: list[str] = []
