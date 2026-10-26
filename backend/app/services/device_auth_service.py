"""
Device authentication service.
Handles device identity verification and authentication state management.
"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.models.device import Device, DeviceCredential
from app.security.device_identity import verify_api_key, hash_api_key
from app.services.audit_service import AuditService


class DeviceAuthService:
    """Manages device authentication lifecycle."""

    @staticmethod
    def authenticate_device(db: Session, device_id: str, api_key: str) -> dict:
        """
        Authenticate a device using its API key.
        Returns authentication result with status details.
        """
        device = db.query(Device).filter(Device.device_id == device_id).first()

        # Unknown device
        if not device:
            AuditService.log_event(
                db=db,
                event_type="UNKNOWN_DEVICE",
                severity="HIGH",
                device_id=device_id,
                description=f"Authentication attempt from unknown device: {device_id}",
                decision="DENY",
            )
            return {
                "authenticated": False,
                "device_id": device_id,
                "message": "Device not registered",
                "status": "unknown",
            }

        # Revoked device
        if device.auth_status == "revoked" or device.status == "revoked":
            AuditService.log_event(
                db=db,
                event_type="AUTH_FAILURE",
                severity="HIGH",
                device_id=device_id,
                description=f"Authentication attempt from revoked device: {device_id}",
                decision="DENY",
            )
            return {
                "authenticated": False,
                "device_id": device_id,
                "message": "Device has been revoked",
                "status": "revoked",
            }

        # Quarantined device
        if device.is_quarantined:
            AuditService.log_event(
                db=db,
                event_type="AUTH_FAILURE",
                severity="MEDIUM",
                device_id=device_id,
                description=f"Authentication attempt from quarantined device: {device_id}",
                decision="DENY",
            )
            return {
                "authenticated": False,
                "device_id": device_id,
                "message": "Device is quarantined",
                "status": "quarantined",
            }

        # Verify API key against stored credentials
        credentials = (
            db.query(DeviceCredential)
            .filter(
                DeviceCredential.device_id == device.id,
                DeviceCredential.credential_type == "api_key",
                DeviceCredential.is_active == True,
            )
            .all()
        )

        authenticated = False
        for cred in credentials:
            if verify_api_key(api_key, cred.credential_hash):
                authenticated = True
                break

        if not authenticated:
            # Log failure and potentially increase risk
            AuditService.log_event(
                db=db,
                event_type="AUTH_FAILURE",
                severity="MEDIUM",
                device_id=device_id,
                description=f"Invalid API key for device: {device_id}",
                decision="DENY",
                risk_before=device.risk_score,
            )
            device.auth_status = "failed"
            db.commit()
            return {
                "authenticated": False,
                "device_id": device_id,
                "message": "Invalid credentials",
                "status": "failed",
            }

        # Success
        device.auth_status = "authenticated"
        device.status = "active"
        device.last_seen = datetime.now(timezone.utc)
        db.commit()

        AuditService.log_event(
            db=db,
            event_type="AUTH_SUCCESS",
            severity="INFO",
            device_id=device_id,
            description=f"Device '{device.name}' authenticated successfully",
        )

        return {
            "authenticated": True,
            "device_id": device_id,
            "message": "Authentication successful",
            "status": "authenticated",
        }

    @staticmethod
    def revoke_device(db: Session, device_id: str, user_id: Optional[int] = None) -> bool:
        """Revoke a device's authentication credentials."""
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device:
            return False

        device.auth_status = "revoked"
        device.status = "revoked"

        # Deactivate all credentials
        db.query(DeviceCredential).filter(
            DeviceCredential.device_id == device.id
        ).update({"is_active": False})

        AuditService.log_event(
            db=db,
            event_type="DEVICE_REVOKED",
            severity="HIGH",
            device_id=device_id,
            description=f"Device '{device.name}' credentials revoked",
            user_id=user_id,
        )

        db.commit()
        return True
