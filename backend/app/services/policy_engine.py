"""
Policy evaluation engine.
Evaluates policies by priority order to determine access decisions.
Supports device-specific, device-type, resource-based, action-based, and time-based rules.
"""
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.policy import Policy
from app.models.device import Device


class PolicyDecision:
    """Represents a policy evaluation result."""
    def __init__(self, decision: str, reason: str, policy_name: Optional[str] = None, policy_id: Optional[int] = None):
        self.decision = decision
        self.reason = reason
        self.policy_name = policy_name
        self.policy_id = policy_id


class PolicyEngine:
    """Evaluates authorization policies for device actions."""

    @staticmethod
    def evaluate(
        db: Session,
        device_id: str,
        resource: str,
        action: str,
        device_type: Optional[str] = None,
        network_zone: Optional[str] = None,
    ) -> PolicyDecision:
        """
        Evaluate policies for a device action.
        Policies are checked in priority order (highest first).
        First matching policy wins.
        """
        # Get all active policies, ordered by priority (highest first)
        policies = (
            db.query(Policy)
            .filter(Policy.is_active == True)
            .order_by(desc(Policy.priority))
            .all()
        )

        for policy in policies:
            if PolicyEngine._matches(policy, device_id, resource, action, device_type, network_zone):
                # Check time constraints
                if policy.time_start and policy.time_end:
                    if not PolicyEngine._check_time_window(policy.time_start, policy.time_end):
                        continue  # Outside time window, skip this policy

                return PolicyDecision(
                    decision=policy.decision,
                    reason=f"Matched policy: {policy.name}",
                    policy_name=policy.name,
                    policy_id=policy.id,
                )

        # Default deny if no policy matches
        return PolicyDecision(
            decision="DENY",
            reason="No matching policy found — default deny",
            policy_name=None,
            policy_id=None,
        )

    @staticmethod
    def _matches(
        policy: Policy,
        device_id: str,
        resource: str,
        action: str,
        device_type: Optional[str] = None,
        network_zone: Optional[str] = None,
    ) -> bool:
        """Check if a policy matches the given request parameters."""
        # Device ID match (null = any device)
        if policy.device_id and policy.device_id != device_id:
            return False

        # Device type match (null = any type)
        if policy.device_type and device_type and policy.device_type != device_type:
            return False

        # Resource match (null = any resource)
        if policy.resource and policy.resource != resource:
            return False

        # Action match (null = any action)
        if policy.action and policy.action != action:
            return False

        # Network zone match (null = any zone)
        if policy.network_zone and network_zone and policy.network_zone != network_zone:
            return False

        return True

    @staticmethod
    def _check_time_window(time_start: str, time_end: str) -> bool:
        """Check if the current time is within the policy's time window."""
        try:
            now = datetime.now(timezone.utc)
            current_time = now.strftime("%H:%M")
            return time_start <= current_time <= time_end
        except (ValueError, TypeError):
            return True  # If time parsing fails, allow the policy

    @staticmethod
    def get_policies(
        db: Session,
        device_id: Optional[str] = None,
        resource: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> List[Policy]:
        """Query policies with optional filters."""
        query = db.query(Policy)
        if device_id:
            query = query.filter((Policy.device_id == device_id) | (Policy.device_id == None))
        if resource:
            query = query.filter((Policy.resource == resource) | (Policy.resource == None))
        if is_active is not None:
            query = query.filter(Policy.is_active == is_active)
        return query.order_by(desc(Policy.priority)).all()

    @staticmethod
    def create_policy(db: Session, policy_data: dict, user_id: Optional[int] = None) -> Policy:
        """Create a new policy."""
        policy = Policy(**policy_data, created_by=user_id)
        db.add(policy)
        db.commit()
        db.refresh(policy)
        return policy

    @staticmethod
    def update_policy(db: Session, policy_id: int, updates: dict) -> Optional[Policy]:
        """Update an existing policy."""
        policy = db.query(Policy).filter(Policy.id == policy_id).first()
        if not policy:
            return None
        for key, value in updates.items():
            if hasattr(policy, key) and value is not None:
                setattr(policy, key, value)
        db.commit()
        db.refresh(policy)
        return policy

    @staticmethod
    def delete_policy(db: Session, policy_id: int) -> bool:
        """Delete a policy."""
        policy = db.query(Policy).filter(Policy.id == policy_id).first()
        if not policy:
            return False
        db.delete(policy)
        db.commit()
        return True
