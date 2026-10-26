"""
Telemetry ingestion API endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, Header, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.device_service import DeviceService
from app.services.telemetry_service import TelemetryService
from app.services.risk_engine import RiskEngine
from app.services.quarantine_service import QuarantineService
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/telemetry", tags=["Telemetry"])


class TelemetryPayload(BaseModel):
    device_id: str
    data_type: str = "sensor_data"
    metrics: dict
    is_anomalous: bool = False


@router.post("")
def ingest_telemetry(
    payload: TelemetryPayload,
    x_device_id: str = Header(..., alias="X-Device-ID"),
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """Ingest telemetry data from an authenticated device."""
    # Verify device exists and is not quarantined
    device = DeviceService.get_device(db, payload.device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{payload.device_id}' not found")

    if device.is_quarantined:
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: Device '{payload.device_id}' is QUARANTINED due to high risk score ({device.risk_score}).",
        )

    if device.status == "restricted":
        # Check if restricted devices can send telemetry
        pass

    # Handle anomalous telemetry
    if payload.is_anomalous:
        RiskEngine.increase_risk(
            db=db,
            device_id=payload.device_id,
            event_type="anomalous_telemetry",
            reason="Anomalous payload pattern detected",
        )
        threshold_action = RiskEngine.check_thresholds(db, payload.device_id)
        if threshold_action == "QUARANTINE":
            QuarantineService.quarantine_device(
                db=db,
                device_id=payload.device_id,
                reason="Automatic quarantine triggered by high risk score",
            )

    # Record telemetry
    telemetry = TelemetryService.ingest(
        db=db,
        device_id=payload.device_id,
        data_type=payload.data_type,
        payload=payload.metrics,
        is_anomalous=payload.is_anomalous,
    )

    # Refresh device state for response summary
    db.refresh(device)

    return {
        "status": "accepted",
        "device_id": device.device_id,
        "risk_score": device.risk_score,
        "risk_level": device.risk_level,
        "quarantined": device.is_quarantined,
        "message": "Telemetry processed successfully",
    }
