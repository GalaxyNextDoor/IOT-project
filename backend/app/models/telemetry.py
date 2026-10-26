"""
Telemetry model for storing device sensor data.
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class Telemetry(Base):
    __tablename__ = "telemetry"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    data_type = Column(String(50), nullable=False)  # temperature, humidity, motion, door_state, light_level
    payload_json = Column(Text, nullable=False)  # JSON string of telemetry data
    is_anomalous = Column(Boolean, default=False)

    # Relationships
    device = relationship("Device", back_populates="telemetry")
