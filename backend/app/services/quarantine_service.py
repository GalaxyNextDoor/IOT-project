"""
Quarantine service.
Manages automatic and manual device quarantine/release.
"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.models.device import Device
from app.models.quarantine import QuarantineEvent
from app.services.audit_service import AuditService
from app.config import settings


class QuarantineService:
    """Manages device quarantine lifecycle."""

    @staticmethod
    def auto_quarantine(db: Session, device_id: str, reason: str) -> bool:
        """
        Automatically quarantine a device when risk threshold is exceeded.
        Returns True if quarantine was applied.
        """
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device or device.is_quarantined:
            return False

        device.is_quarantined = True
        device.status = "quarantined"
        device.quarantined_at = datetime.now(timezone.utc)

        # Record quarantine event
        q_event = QuarantineEvent(
            device_id=device.id,
            action="QUARANTINED",
            reason=reason,
            risk_score_at_action=device.risk_score,
        )
        db.add(q_event)

        AuditService.log_event(
            db=db,
            event_type="DEVICE_QUARANTINED",
            severity="CRITICAL",
            device_id=device_id,
            description=f"Device auto-quarantined: {reason}",
            risk_before=device.risk_score,
            risk_after=device.risk_score,
        )

        db.commit()
        return True

    @staticmethod
    def restrict_device(db: Session, device_id: str, reason: str) -> bool:
        """
        Restrict a device (intermediate state before quarantine).
        """
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device or device.is_quarantined:
            return False

        device.status = "restricted"

        AuditService.log_event(
            db=db,
            event_type="DEVICE_RESTRICTED",
            severity="HIGH",
            device_id=device_id,
            description=f"Device restricted: {reason}",
            risk_before=device.risk_score,
            risk_after=device.risk_score,
        )

        db.commit()
        return True

    @staticmethod
    def manual_quarantine(db: Session, device_id: str, reason: str, user_id: int) -> bool:
        """Manually quarantine a device (admin action)."""
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device:
            return False

        device.is_quarantined = True
        device.status = "quarantined"
        device.quarantined_at = datetime.now(timezone.utc)

        q_event = QuarantineEvent(
            device_id=device.id,
            action="QUARANTINED",
            reason=reason,
            risk_score_at_action=device.risk_score,
            performed_by=user_id,
        )
        db.add(q_event)

        AuditService.log_event(
            db=db,
            event_type="DEVICE_QUARANTINED",
            severity="HIGH",
            device_id=device_id,
            description=f"Device manually quarantined by admin: {reason}",
            user_id=user_id,
        )

        db.commit()
        return True

    @staticmethod
    def release_device(db: Session, device_id: str, user_id: int) -> bool:
        """Release a device from quarantine (admin action)."""
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device or not device.is_quarantined:
            return False

        device.is_quarantined = False
        device.status = "active"
        device.quarantined_at = None

        q_event = QuarantineEvent(
            device_id=device.id,
            action="RELEASED",
            reason="Released by administrator",
            risk_score_at_action=device.risk_score,
            performed_by=user_id,
        )
        db.add(q_event)

        AuditService.log_event(
            db=db,
            event_type="DEVICE_RELEASED",
            severity="INFO",
            device_id=device_id,
            description=f"Device released from quarantine by admin",
            user_id=user_id,
        )

        db.commit()
        return True

    @staticmethod
    def check_and_enforce(db: Session, device_id: str) -> Optional[str]:
        """
        Check risk thresholds and automatically enforce quarantine/restriction.
        Called after every risk increase.
        Returns the action taken: 'QUARANTINED', 'RESTRICTED', or None.
        """
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device or device.is_quarantined:
            return None

        if device.risk_score >= settings.RISK_QUARANTINE_THRESHOLD:
            QuarantineService.auto_quarantine(
                db, device_id,
                f"Risk score ({device.risk_score:.1f}) exceeded quarantine threshold ({settings.RISK_QUARANTINE_THRESHOLD})"
            )
            return "QUARANTINED"
        elif device.risk_score >= settings.RISK_RESTRICT_THRESHOLD and device.status != "restricted":
            QuarantineService.restrict_device(
                db, device_id,
                f"Risk score ({device.risk_score:.1f}) exceeded restriction threshold ({settings.RISK_RESTRICT_THRESHOLD})"
            )
            return "RESTRICTED"

        return None
