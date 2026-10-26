"""
Pydantic schemas for authentication.
"""
from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class DeviceAuthRequest(BaseModel):
    device_id: str
    api_key: str


class DeviceAuthResponse(BaseModel):
    authenticated: bool
    device_id: str
    message: str
    status: str
