"""
Pydantic schemas for risk engine.
"""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class RiskScoreResponse(BaseModel):
    device_id: str
    risk_score: float
    risk_level: str
    history: List[dict]  # List of risk events


class RiskFactors(BaseModel):
    """Configurable risk factor weights."""
    auth_failure: float = 10.0
    unauthorized_action: float = 20.0
    excessive_message_rate: float = 15.0
    unknown_destination: float = 20.0
    repeated_policy_violations: float = 10.0
    suspicious_behavior: float = 15.0
    decay_rate_per_minute: float = 1.0
