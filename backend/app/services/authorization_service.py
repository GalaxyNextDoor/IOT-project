"""
Authorization service.
Combines policy evaluation with risk assessment for adaptive access control.
This is the central decision point for Zero-Trust authorization.
"""
from typing import Optional
from sqlalchemy.orm import Session
from app.models.device import Device
from app.services.policy_engine import PolicyEngine
from app.services.risk_engine import RiskEngine
from app.services.quarantine_service import QuarantineService
from app.services.audit_service import AuditService
from app.config import settings


class AuthorizationDecision:
    """Represents a complete authorization decision."""
    def __init__(
        self,
        decision: str,
        reason: str,
        device_id: str,
        resource: str,
        action: str,
        risk_score: float,
        risk_level: str,
        policy_name: Optional[str] = None,
    ):
        self.decision = decision
        self.reason = reason
        self.device_id = device_id
        self.resource = resource
        self.action = action
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.policy_name = policy_name


class AuthorizationService:
    """
    Central authorization service implementing Zero-Trust adaptive access control.
    
    Decision flow:
    1. Check device exists and is authenticated
    2. Check if device is quarantined
    3. Evaluate policy
    4. Apply risk-based adaptive access control
    5. Log decision
    6. Return result
    """

    @staticmethod
    def authorize(
        db: Session,
        device_id: str,
        resource: str,
        action: str,
    ) -> AuthorizationDecision:
        """
        Authorize a device action request.
        Never trusts a device merely because it is connected.
        """
        device = db.query(Device).filter(Device.device_id == device_id).first()

        # Step 1: Device must exist
        if not device:
            AuditService.log_event(
                db=db,
                event_type="AUTHORIZATION_DENIED",
                severity="HIGH",
                device_id=device_id,
                description=f"Unknown device attempted: {resource}.{action}",
                requested_action=f"{resource}.{action}",
                decision="DENY",
            )
            return AuthorizationDecision(
                decision="DENY",
                reason="Device not registered",
                device_id=device_id,
                resource=resource,
                action=action,
                risk_score=0,
                risk_level="UNKNOWN",
            )

        # Step 2: Device must be authenticated
        if device.auth_status != "authenticated":
            AuditService.log_event(
                db=db,
                event_type="AUTHORIZATION_DENIED",
                severity="MEDIUM",
                device_id=device_id,
                description=f"Unauthenticated device attempted: {resource}.{action}",
                requested_action=f"{resource}.{action}",
                decision="DENY",
                risk_before=device.risk_score,
            )
            return AuthorizationDecision(
                decision="DENY",
                reason=f"Device not authenticated (status: {device.auth_status})",
                device_id=device_id,
                resource=resource,
                action=action,
                risk_score=device.risk_score,
                risk_level=device.risk_level,
            )

        # Step 3: Check quarantine
        if device.is_quarantined:
            AuditService.log_event(
                db=db,
                event_type="AUTHORIZATION_DENIED",
                severity="HIGH",
                device_id=device_id,
                description=f"Quarantined device attempted: {resource}.{action}",
                requested_action=f"{resource}.{action}",
                decision="DENY",
                risk_before=device.risk_score,
            )
            return AuthorizationDecision(
                decision="DENY",
                reason="Device is quarantined",
                device_id=device_id,
                resource=resource,
                action=action,
                risk_score=device.risk_score,
                risk_level=device.risk_level,
            )

        # Step 4: Evaluate policy
        policy_decision = PolicyEngine.evaluate(
            db=db,
            device_id=device_id,
            resource=resource,
            action=action,
            device_type=device.device_type,
        )

        # Step 5: Apply risk-based adaptive access control
        final_decision = policy_decision.decision
        reason = policy_decision.reason

        if device.risk_score >= settings.RISK_QUARANTINE_THRESHOLD:
            final_decision = "QUARANTINE"
            reason = f"Risk score ({device.risk_score:.1f}) exceeds quarantine threshold — action blocked"
            # Trigger quarantine
            QuarantineService.check_and_enforce(db, device_id)
        elif device.risk_score >= settings.RISK_RESTRICT_THRESHOLD and policy_decision.decision == "ALLOW":
            final_decision = "RESTRICT"
            reason = f"Policy allows action, but risk score ({device.risk_score:.1f}) requires restriction"
            QuarantineService.check_and_enforce(db, device_id)

        # Step 6: Handle denied actions (increase risk for unauthorized attempts)
        if final_decision == "DENY" and policy_decision.decision == "DENY":
            risk_before = device.risk_score
            RiskEngine.increase_risk(
                db=db,
                device_id=device_id,
                event_type="unauthorized_action",
                reason=f"Unauthorized action attempt: {resource}.{action}",
            )
            # Re-fetch to get updated score
            db.refresh(device)
            QuarantineService.check_and_enforce(db, device_id)
            db.refresh(device)

            AuditService.log_event(
                db=db,
                event_type="AUTHORIZATION_DENIED",
                severity="HIGH",
                device_id=device_id,
                description=f"Policy denied: {resource}.{action}",
                requested_action=f"{resource}.{action}",
                decision="DENY",
                risk_before=risk_before,
                risk_after=device.risk_score,
            )
        elif final_decision == "ALLOW":
            AuditService.log_event(
                db=db,
                event_type="AUTHORIZATION_GRANTED",
                severity="INFO",
                device_id=device_id,
                description=f"Action authorized: {resource}.{action}",
                requested_action=f"{resource}.{action}",
                decision="ALLOW",
                risk_before=device.risk_score,
            )
        else:
            # RESTRICT or QUARANTINE
            severity = "CRITICAL" if final_decision == "QUARANTINE" else "HIGH"
            AuditService.log_event(
                db=db,
                event_type="AUTHORIZATION_DENIED",
                severity=severity,
                device_id=device_id,
                description=f"Action {final_decision}: {resource}.{action} — {reason}",
                requested_action=f"{resource}.{action}",
                decision=final_decision,
                risk_before=device.risk_score,
            )

        return AuthorizationDecision(
            decision=final_decision,
            reason=reason,
            device_id=device_id,
            resource=resource,
            action=action,
            risk_score=device.risk_score,
            risk_level=device.risk_level,
            policy_name=policy_decision.policy_name,
        )
