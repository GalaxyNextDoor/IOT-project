"""
Risk scoring engine.
Maintains transparent, explainable risk scores for each device.
"""
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.device import Device
from app.models.event import RiskEvent
from app.config import settings


# Risk factor weights
RISK_FACTORS = {
    "auth_failure": 10.0,
    "unauthorized_action": 20.0,
    "excessive_message_rate": 15.0,
    "unknown_destination": 20.0,
    "repeated_policy_violations": 10.0,
    "suspicious_behavior": 15.0,
    "anomalous_telemetry": 10.0,
}


def _get_risk_level(score: float) -> str:
    """Convert numeric risk score to level string."""
    if score <= 30:
        return "LOW"
    elif score <= 60:
        return "MEDIUM"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"


class RiskEngine:
    """Manages device risk scoring with full transparency."""

    @staticmethod
    def increase_risk(
        db: Session,
        device_id: str,
        event_type: str,
        reason: str,
        custom_delta: Optional[float] = None,
    ) -> Optional[Device]:
        """
        Increase a device's risk score based on an event.
        Returns the updated device or None if not found.
        """
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device:
            return None

        delta = custom_delta if custom_delta is not None else RISK_FACTORS.get(event_type, 10.0)
        risk_before = device.risk_score
        device.risk_score = min(100.0, device.risk_score + delta)
        device.risk_level = _get_risk_level(device.risk_score)

        # Record risk event
        risk_event = RiskEvent(
            device_id=device.id,
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            risk_delta=delta,
            risk_before=risk_before,
            risk_after=device.risk_score,
            reason=reason,
        )
        db.add(risk_event)
        db.commit()
        db.refresh(device)
        return device

    @staticmethod
    def decrease_risk(
        db: Session,
        device_id: str,
        amount: float,
        reason: str = "Normal behavior decay",
    ) -> Optional[Device]:
        """Decrease a device's risk score (e.g., after normal behavior)."""
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device:
            return None

        risk_before = device.risk_score
        device.risk_score = max(0.0, device.risk_score - amount)
        device.risk_level = _get_risk_level(device.risk_score)

        risk_event = RiskEvent(
            device_id=device.id,
            timestamp=datetime.now(timezone.utc),
            event_type="risk_decay",
            risk_delta=-amount,
            risk_before=risk_before,
            risk_after=device.risk_score,
            reason=reason,
        )
        db.add(risk_event)
        db.commit()
        db.refresh(device)
        return device

    @staticmethod
    def reset_risk(
        db: Session,
        device_id: str,
        reason: str = "Manual risk reset by administrator",
    ) -> Optional[Device]:
        """Reset a device's risk score to 0."""
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device:
            return None

        risk_before = device.risk_score
        device.risk_score = 0.0
        device.risk_level = "LOW"

        risk_event = RiskEvent(
            device_id=device.id,
            timestamp=datetime.now(timezone.utc),
            event_type="risk_reset",
            risk_delta=-risk_before,
            risk_before=risk_before,
            risk_after=0.0,
            reason=reason,
        )
        db.add(risk_event)
        db.commit()
        db.refresh(device)
        return device

    @staticmethod
    def get_risk_history(db: Session, device_id: str, limit: int = 50) -> List[RiskEvent]:
        """Get risk event history for a device."""
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device:
            return []
        return (
            db.query(RiskEvent)
            .filter(RiskEvent.device_id == device.id)
            .order_by(desc(RiskEvent.timestamp))
            .limit(limit)
            .all()
        )

    @staticmethod
    def check_thresholds(db: Session, device_id: str) -> Optional[str]:
        """
        Check if a device has crossed risk thresholds.
        Returns: 'QUARANTINE', 'RESTRICT', or None
        """
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device:
            return None

        if device.risk_score >= settings.RISK_QUARANTINE_THRESHOLD:
            return "QUARANTINE"
        elif device.risk_score >= settings.RISK_RESTRICT_THRESHOLD:
            return "RESTRICT"
        return None
