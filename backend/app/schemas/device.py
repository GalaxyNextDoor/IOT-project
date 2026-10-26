"""
Pydantic schemas for devices.
"""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class DeviceBase(BaseModel):
    device_id: str
    name: str
    device_type: str
    description: Optional[str] = None
    manufacturer: Optional[str] = "Espressif"
    firmware_version: Optional[str] = "1.0.0"
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    firmware_version: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    status: Optional[str] = None


class PermissionResponse(BaseModel):
    id: int
    name: str
    resource: str
    action: str
    decision: str

    model_config = {"from_attributes": True}


class DeviceResponse(DeviceBase):
    id: int
    status: str
    auth_status: str
    risk_score: float
    risk_level: str
    certificate_status: Optional[str] = None
    is_quarantined: bool
    last_seen: Optional[datetime] = None
    registered_at: datetime
    quarantined_at: Optional[datetime] = None
    api_key: Optional[str] = None  # Only returned on registration

    model_config = {"from_attributes": True}


class DeviceListResponse(BaseModel):
    devices: List[DeviceResponse]
    total: int


class DeviceBriefResponse(BaseModel):
    """Minimal device info for lists and cards."""
    id: int
    device_id: str
    name: str
    device_type: str
    status: str
    auth_status: str
    risk_score: float
    risk_level: str
    is_quarantined: bool
    last_seen: Optional[datetime] = None

    model_config = {"from_attributes": True}
