"""
Device management and authentication API endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from typing import Optional, List
from app.database import get_db
from app.schemas.device import DeviceCreate, DeviceResponse
from app.services.device_service import DeviceService
from app.services.device_auth_service import DeviceAuthService

router = APIRouter(prefix="/api/v1/devices", tags=["Devices"])


@router.post("/register")
def register_device(device_data: DeviceCreate, db: Session = Depends(get_db)):
    """Register a new IoT device and receive an API key."""
    try:
        device, api_key = DeviceService.register_device(db, device_data)
        return {
            "status": "success",
            "device_id": device.device_id,
            "name": device.name,
            "api_key": api_key,
            "message": "Device registered successfully. Keep the API key safe.",
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/authenticate")
def authenticate_device(
    x_device_id: str = Header(..., alias="X-Device-ID"),
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """Authenticate an IoT device using its ID and API key."""
    result = DeviceAuthService.authenticate_device(db, x_device_id, x_api_key)
    if not result["authenticated"]:
        raise HTTPException(status_code=403, detail=result["message"])
    return result


@router.get("", response_model=List[DeviceResponse])
def list_devices(status: Optional[str] = None, db: Session = Depends(get_db)):
    """List registered devices."""
    return DeviceService.list_devices(db, status=status)
