"""
Pydantic schemas for attack simulation.
"""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class SimulationRequest(BaseModel):
    attack_type: str  # unknown_device, auth_brute_force, unauthorized_command, message_flood, suspicious_behavior
    target_device_id: Optional[str] = None  # For attacks against existing devices
    intensity: int = 1  # 1-5 scale for attack intensity
    description: Optional[str] = None


class SimulationStep(BaseModel):
    step: int
    action: str
    result: str
    risk_before: Optional[float] = None
    risk_after: Optional[float] = None
    event_type: Optional[str] = None
    timestamp: datetime


class SimulationResponse(BaseModel):
    attack_type: str
    target_device_id: Optional[str] = None
    success: bool
    steps: List[SimulationStep]
    summary: str
    total_risk_change: float
    final_device_status: Optional[str] = None
