"""
Risk management API endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.risk_engine import RiskEngine
from app.services.quarantine_service import QuarantineService
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api/v1/risk", tags=["Risk Engine"])


class RiskIncreaseRequest(BaseModel):
    device_id: str
    event_type: str = "suspicious_behavior"
    reason: str = "Manual security alert trigger"
    custom_delta: Optional[float] = None


class RiskResetRequest(BaseModel):
    device_id: str
    reason: str = "Manual admin risk reset"


@router.post("/increase")
def increase_risk(payload: RiskIncreaseRequest, db: Session = Depends(get_db)):
    """Manually increase a device's risk score."""
    device = RiskEngine.increase_risk(
        db=db,
        device_id=payload.device_id,
        event_type=payload.event_type,
        reason=payload.reason,
        custom_delta=payload.custom_delta,
    )
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    action = RiskEngine.check_thresholds(db, payload.device_id)
    if action == "QUARANTINE":
        QuarantineService.quarantine_device(db, payload.device_id, reason=f"Triggered by event {payload.event_type}")

    db.refresh(device)
    return {
        "status": "success",
        "device_id": device.device_id,
        "new_risk_score": device.risk_score,
        "risk_level": device.risk_level,
        "is_quarantined": device.is_quarantined,
        "action_taken": action,
    }


@router.post("/reset")
def reset_risk(payload: RiskResetRequest, db: Session = Depends(get_db)):
    """Reset a device's risk score and un-quarantine it."""
    device = RiskEngine.reset_risk(db, payload.device_id, reason=payload.reason)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    QuarantineService.unquarantine_device(db, payload.device_id, reason="Risk score reset to zero")
    db.refresh(device)
    return {
        "status": "success",
        "device_id": device.device_id,
        "risk_score": device.risk_score,
        "risk_level": device.risk_level,
        "is_quarantined": device.is_quarantined,
    }
