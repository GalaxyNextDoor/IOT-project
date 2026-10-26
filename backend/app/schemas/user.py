"""
Pydantic schemas for admin users.
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    username: str
    email: str
    role: str = "admin"


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = {"from_attributes": True}
