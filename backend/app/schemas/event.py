"""
Pydantic schemas for security events.
"""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class SecurityEventResponse(BaseModel):
    id: int
    timestamp: datetime
    device_id: Optional[str] = None
    event_type: str
    severity: str
    description: Optional[str] = None
    requested_action: Optional[str] = None
    decision: Optional[str] = None
    risk_before: Optional[float] = None
    risk_after: Optional[float] = None
    source_ip: Optional[str] = None
    details_json: Optional[str] = None

    model_config = {"from_attributes": True}


class SecurityEventListResponse(BaseModel):
    events: List[SecurityEventResponse]
    total: int


class RiskEventResponse(BaseModel):
    id: int
    device_id: int
    timestamp: datetime
    event_type: str
    risk_delta: float
    risk_before: float
    risk_after: float
    reason: Optional[str] = None

    model_config = {"from_attributes": True}
