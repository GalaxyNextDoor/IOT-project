"""
Device lifecycle management service.
Handles registration, updates, deletion, and status management.
"""
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from app.models.device import Device, DeviceCredential
from app.schemas.device import DeviceCreate, DeviceUpdate
from app.security.device_identity import generate_api_key, hash_api_key
from app.services.audit_service import AuditService


class DeviceService:
    """Manages device CRUD operations and lifecycle."""

    @staticmethod
    def register_device(db: Session, device_data: DeviceCreate, user_id: Optional[int] = None) -> Tuple[Device, str]:
        """
        Register a new device. Returns the device and its plaintext API key.
        The API key is only returned once — it is stored as a hash.
        """
        # Check if device_id already exists
        existing = db.query(Device).filter(Device.device_id == device_data.device_id).first()
        if existing:
            raise ValueError(f"Device with ID '{device_data.device_id}' already exists")

        # Create device
        device = Device(
            device_id=device_data.device_id,
            name=device_data.name,
            device_type=device_data.device_type,
            description=device_data.description,
            manufacturer=device_data.manufacturer,
            firmware_version=device_data.firmware_version,
            ip_address=device_data.ip_address,
            mac_address=device_data.mac_address,
            status="registered",
            auth_status="unauthenticated",
            risk_score=0.0,
            risk_level="LOW",
            registered_by=user_id,
        )
        db.add(device)
        db.flush()  # Get the device.id

        # Generate API key credential
        api_key = generate_api_key()
        credential = DeviceCredential(
            device_id=device.id,
            credential_type="api_key",
            credential_hash=hash_api_key(api_key),
            api_key=api_key[:8] + "...",  # Store prefix for identification
            is_active=True,
        )
        db.add(credential)

        # Log the registration
        AuditService.log_event(
            db=db,
            event_type="DEVICE_REGISTERED",
            severity="INFO",
            device_id=device.device_id,
            description=f"Device '{device.name}' ({device.device_type}) registered",
            user_id=user_id,
        )

        db.commit()
        db.refresh(device)
        return device, api_key

    @staticmethod
    def get_device(db: Session, device_id: str) -> Optional[Device]:
        """Get a device by its string device_id."""
        return db.query(Device).filter(Device.device_id == device_id).first()

    @staticmethod
    def get_device_by_pk(db: Session, pk: int) -> Optional[Device]:
        """Get a device by its primary key."""
        return db.query(Device).filter(Device.id == pk).first()

    @staticmethod
    def list_devices(db: Session, status: Optional[str] = None, device_type: Optional[str] = None) -> List[Device]:
        """List all devices with optional filters."""
        query = db.query(Device)
        if status:
            query = query.filter(Device.status == status)
        if device_type:
            query = query.filter(Device.device_type == device_type)
        return query.order_by(Device.registered_at.desc()).all()

    @staticmethod
    def update_device(db: Session, device_id: str, updates: DeviceUpdate, user_id: Optional[int] = None) -> Optional[Device]:
        """Update a device's fields."""
        device = DeviceService.get_device(db, device_id)
        if not device:
            return None

        update_data = updates.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(device, field, value)

        AuditService.log_event(
            db=db,
            event_type="DEVICE_MODIFIED",
            severity="INFO",
            device_id=device.device_id,
            description=f"Device updated: {', '.join(update_data.keys())}",
            user_id=user_id,
        )

        db.commit()
        db.refresh(device)
        return device

    @staticmethod
    def delete_device(db: Session, device_id: str, user_id: Optional[int] = None) -> bool:
        """Delete a device and all associated records."""
        device = DeviceService.get_device(db, device_id)
        if not device:
            return False

        AuditService.log_event(
            db=db,
            event_type="DEVICE_DELETED",
            severity="MEDIUM",
            device_id=device.device_id,
            description=f"Device '{device.name}' deleted",
            user_id=user_id,
        )

        db.delete(device)
        db.commit()
        return True

    @staticmethod
    def update_last_seen(db: Session, device_id: str) -> None:
        """Update the last_seen timestamp for a device."""
        device = DeviceService.get_device(db, device_id)
        if device:
            device.last_seen = datetime.now(timezone.utc)
            db.commit()

    @staticmethod
    def get_device_stats(db: Session) -> dict:
        """Get aggregated device statistics for the dashboard."""
        from sqlalchemy import func
        total = db.query(func.count(Device.id)).scalar()
        active = db.query(func.count(Device.id)).filter(Device.status == "active").scalar()
        quarantined = db.query(func.count(Device.id)).filter(Device.is_quarantined == True).scalar()
        restricted = db.query(func.count(Device.id)).filter(Device.status == "restricted").scalar()

        # Count by risk level
        low_risk = db.query(func.count(Device.id)).filter(Device.risk_level == "LOW").scalar()
        medium_risk = db.query(func.count(Device.id)).filter(Device.risk_level == "MEDIUM").scalar()
        high_risk = db.query(func.count(Device.id)).filter(Device.risk_level == "HIGH").scalar()
        critical_risk = db.query(func.count(Device.id)).filter(Device.risk_level == "CRITICAL").scalar()

        return {
            "total": total,
            "active": active,
            "quarantined": quarantined,
            "restricted": restricted,
            "trusted": low_risk,
            "risk_distribution": {
                "LOW": low_risk,
                "MEDIUM": medium_risk,
                "HIGH": high_risk,
                "CRITICAL": critical_risk,
            },
        }
