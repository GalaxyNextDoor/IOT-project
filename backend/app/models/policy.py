"""
Policy, Permission, and DevicePermission models.
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)  # e.g., sensor.publish, door.control
    resource = Column(String(50), nullable=False)  # e.g., sensor, door, motion, device
    action = Column(String(50), nullable=False)  # e.g., read, publish, control, configure
    description = Column(Text, nullable=True)

    # Relationships
    device_permissions = relationship("DevicePermission", back_populates="permission", cascade="all, delete-orphan")


class DevicePermission(Base):
    __tablename__ = "device_permissions"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    permission_id = Column(Integer, ForeignKey("permissions.id"), nullable=False)
    decision = Column(String(20), nullable=False, default="ALLOW")  # ALLOW, DENY
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Relationships
    device = relationship("Device", back_populates="permissions")
    permission = relationship("Permission", back_populates="device_permissions")


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)

    # Matching criteria (all nullable — null means "match any")
    device_id = Column(String(100), nullable=True, index=True)  # Specific device or null for any
    device_type = Column(String(50), nullable=True)  # Match by device type
    resource = Column(String(50), nullable=True)  # e.g., sensor, door, motion
    action = Column(String(50), nullable=True)  # e.g., read, publish, control

    # Decision
    decision = Column(String(20), nullable=False, default="DENY")  # ALLOW, DENY, RESTRICT

    # Priority (higher = evaluated first)
    priority = Column(Integer, nullable=False, default=0)
    is_active = Column(Boolean, default=True)

    # Optional constraints
    time_start = Column(String(5), nullable=True)  # HH:MM format
    time_end = Column(String(5), nullable=True)
    network_zone = Column(String(50), nullable=True)
    risk_threshold = Column(Integer, nullable=True)  # Max risk score for this policy to apply

    # Audit
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
