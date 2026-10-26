"""
QuarantineEvent model for tracking device quarantine/release history.
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class QuarantineEvent(Base):
    __tablename__ = "quarantine_events"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    action = Column(String(20), nullable=False)  # QUARANTINED, RELEASED, REVOKED, RISK_RESET
    reason = Column(Text, nullable=True)
    risk_score_at_action = Column(Float, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    performed_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Relationships
    device = relationship("Device", back_populates="quarantine_events")
    admin = relationship("User", foreign_keys=[performed_by])
