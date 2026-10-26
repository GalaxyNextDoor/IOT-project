"""
Pydantic schemas for telemetry data.
"""
from pydantic import BaseModel
from typing import Optional, List, Any
from datetime import datetime


class TelemetryCreate(BaseModel):
    device_id: str
    data_type: str
    payload: dict  # Will be serialized to JSON for storage


class TelemetryResponse(BaseModel):
    id: int
    device_id: int
    timestamp: datetime
    data_type: str
    payload_json: str
    is_anomalous: bool

    model_config = {"from_attributes": True}


class TelemetryListResponse(BaseModel):
    telemetry: List[TelemetryResponse]
    total: int
