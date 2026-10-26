"""
Pydantic schemas for policies and permissions.
"""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class PermissionBase(BaseModel):
    name: str
    resource: str
    action: str
    description: Optional[str] = None


class PermissionCreate(PermissionBase):
    pass


class PermissionResponse(PermissionBase):
    id: int

    model_config = {"from_attributes": True}


class PolicyBase(BaseModel):
    name: str
    description: Optional[str] = None
    device_id: Optional[str] = None
    device_type: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    decision: str = "DENY"
    priority: int = 0
    is_active: bool = True
    time_start: Optional[str] = None
    time_end: Optional[str] = None
    network_zone: Optional[str] = None
    risk_threshold: Optional[int] = None


class PolicyCreate(PolicyBase):
    pass


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    device_id: Optional[str] = None
    device_type: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    decision: Optional[str] = None
    priority: Optional[int] = None
    is_active: Optional[bool] = None
    time_start: Optional[str] = None
    time_end: Optional[str] = None
    network_zone: Optional[str] = None
    risk_threshold: Optional[int] = None


class PolicyResponse(PolicyBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    created_by: Optional[int] = None

    model_config = {"from_attributes": True}


class PolicyListResponse(BaseModel):
    policies: List[PolicyResponse]
    total: int


class AuthorizationRequest(BaseModel):
    device_id: str
    resource: str
    action: str


class AuthorizationResponse(BaseModel):
    device_id: str
    resource: str
    action: str
    decision: str  # ALLOW, DENY, RESTRICT, QUARANTINE
    reason: str
    risk_score: float
    risk_level: str
    policy_name: Optional[str] = None
