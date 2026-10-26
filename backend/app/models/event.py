"""
SecurityEvent and RiskEvent models for audit logging and risk tracking.
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    device_id = Column(String(100), nullable=True, index=True)  # String device_id, not FK (can log unknown devices)
    event_type = Column(String(50), nullable=False, index=True)
    # Event types: DEVICE_REGISTERED, AUTH_SUCCESS, AUTH_FAILURE, AUTH_REVOKED,
    #   AUTHORIZATION_GRANTED, AUTHORIZATION_DENIED, POLICY_VIOLATION,
    #   RISK_INCREASED, RISK_DECREASED, DEVICE_QUARANTINED, DEVICE_RELEASED,
    #   DEVICE_REVOKED, ADMIN_LOGIN, POLICY_CREATED, POLICY_MODIFIED,
    #   POLICY_DELETED, DEVICE_MODIFIED, ANOMALY_DETECTED, UNKNOWN_DEVICE,
    #   MESSAGE_FLOOD, SUSPICIOUS_BEHAVIOR

    severity = Column(String(20), nullable=False, default="INFO")  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=True)
    requested_action = Column(String(100), nullable=True)
    decision = Column(String(20), nullable=True)  # ALLOW, DENY, RESTRICT, QUARANTINE
    risk_before = Column(Float, nullable=True)
    risk_after = Column(Float, nullable=True)
    source_ip = Column(String(45), nullable=True)
    details_json = Column(Text, nullable=True)  # JSON string for additional details
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)


class RiskEvent(Base):
    __tablename__ = "risk_events"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    event_type = Column(String(50), nullable=False)
    risk_delta = Column(Float, nullable=False)
    risk_before = Column(Float, nullable=False)
    risk_after = Column(Float, nullable=False)
    reason = Column(Text, nullable=True)

    # Relationships
    device = relationship("Device", back_populates="risk_events")
