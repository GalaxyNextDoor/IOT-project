"""
Telemetry ingestion and query service.
"""
import json
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.telemetry import Telemetry
from app.models.device import Device


class TelemetryService:
    """Handles telemetry data ingestion and queries."""

    @staticmethod
    def ingest(
        db: Session,
        device_id: str,
        data_type: str,
        payload: dict,
        is_anomalous: bool = False,
    ) -> Optional[Telemetry]:
        """Ingest a telemetry data point from a device."""
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device:
            return None

        telemetry = Telemetry(
            device_id=device.id,
            timestamp=datetime.now(timezone.utc),
            data_type=data_type,
            payload_json=json.dumps(payload),
            is_anomalous=is_anomalous,
        )
        db.add(telemetry)

        # Update device last seen
        device.last_seen = datetime.now(timezone.utc)
        db.commit()
        db.refresh(telemetry)
        return telemetry

    @staticmethod
    def get_device_telemetry(
        db: Session,
        device_id: str,
        data_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[List[Telemetry], int]:
        """Get telemetry data for a device."""
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device:
            return [], 0

        query = db.query(Telemetry).filter(Telemetry.device_id == device.id)
        if data_type:
            query = query.filter(Telemetry.data_type == data_type)

        total = query.count()
        telemetry = query.order_by(desc(Telemetry.timestamp)).offset(offset).limit(limit).all()
        return telemetry, total
