"""
Device and DeviceCredential models.
"""
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    device_type = Column(String(50), nullable=False)  # temperature_sensor, door_controller, motion_sensor, etc.
    description = Column(Text, nullable=True)
    manufacturer = Column(String(100), nullable=True, default="Espressif")
    firmware_version = Column(String(50), nullable=True, default="1.0.0")
    ip_address = Column(String(45), nullable=True)  # Supports IPv6
    mac_address = Column(String(17), nullable=True)

    # Status fields
    status = Column(String(20), nullable=False, default="registered")  # registered, active, restricted, quarantined, revoked, offline
    auth_status = Column(String(20), nullable=False, default="unauthenticated")  # unauthenticated, authenticated, failed, revoked
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(String(20), nullable=False, default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    certificate_status = Column(String(20), nullable=True, default="none")  # none, valid, expired, revoked
    is_quarantined = Column(Boolean, default=False)

    # Timestamps
    last_seen = Column(DateTime(timezone=True), nullable=True)
    registered_at = Column(DateTime(timezone=True), server_default=func.now())
    quarantined_at = Column(DateTime(timezone=True), nullable=True)

    # Foreign keys
    registered_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Relationships
    credentials = relationship("DeviceCredential", back_populates="device", cascade="all, delete-orphan")
    permissions = relationship("DevicePermission", back_populates="device", cascade="all, delete-orphan")
    telemetry = relationship("Telemetry", back_populates="device", cascade="all, delete-orphan")
    risk_events = relationship("RiskEvent", back_populates="device", cascade="all, delete-orphan")
    quarantine_events = relationship("QuarantineEvent", back_populates="device", cascade="all, delete-orphan")


class DeviceCredential(Base):
    __tablename__ = "device_credentials"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    credential_type = Column(String(30), nullable=False, default="api_key")  # api_key, certificate, pre_shared_key
    credential_hash = Column(String(255), nullable=True)
    api_key = Column(String(255), nullable=True)
    certificate_fingerprint = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    device = relationship("Device", back_populates="credentials")
