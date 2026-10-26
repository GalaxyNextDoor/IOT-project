"""
Audit service for logging all security-relevant events.
Central logging point — all services call this to record events.
"""
import json
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.event import SecurityEvent


class AuditService:
    """Centralized audit logging service."""

    @staticmethod
    def log_event(
        db: Session,
        event_type: str,
        severity: str = "INFO",
        device_id: Optional[str] = None,
        description: Optional[str] = None,
        requested_action: Optional[str] = None,
        decision: Optional[str] = None,
        risk_before: Optional[float] = None,
        risk_after: Optional[float] = None,
        source_ip: Optional[str] = None,
        details: Optional[dict] = None,
        user_id: Optional[int] = None,
    ) -> SecurityEvent:
        """Log a security event to the database."""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            device_id=device_id,
            event_type=event_type,
            severity=severity,
            description=description,
            requested_action=requested_action,
            decision=decision,
            risk_before=risk_before,
            risk_after=risk_after,
            source_ip=source_ip,
            details_json=json.dumps(details) if details else None,
            user_id=user_id,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def get_events(
        db: Session,
        device_id: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[List[SecurityEvent], int]:
        """Query security events with optional filters."""
        query = db.query(SecurityEvent)

        if device_id:
            query = query.filter(SecurityEvent.device_id == device_id)
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        if severity:
            query = query.filter(SecurityEvent.severity == severity)

        total = query.count()
        events = query.order_by(desc(SecurityEvent.timestamp)).offset(offset).limit(limit).all()
        return events, total

    @staticmethod
    def get_recent_events(db: Session, hours: int = 24, limit: int = 50) -> List[SecurityEvent]:
        """Get events from the last N hours."""
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return (
            db.query(SecurityEvent)
            .filter(SecurityEvent.timestamp >= cutoff)
            .order_by(desc(SecurityEvent.timestamp))
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_event_counts_by_severity(db: Session, hours: int = 24) -> dict:
        """Get event counts grouped by severity for the last N hours."""
        from datetime import timedelta
        from sqlalchemy import func
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        results = (
            db.query(SecurityEvent.severity, func.count(SecurityEvent.id))
            .filter(SecurityEvent.timestamp >= cutoff)
            .group_by(SecurityEvent.severity)
            .all()
        )
        return {severity: count for severity, count in results}
