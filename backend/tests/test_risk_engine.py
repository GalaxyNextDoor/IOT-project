"""
Tests for the Risk Engine service.
"""
from app.services.risk_engine import RiskEngine


def test_increase_risk(db_session, sample_device):
    """Test increasing device risk score."""
    initial_score = sample_device.risk_score

    updated = RiskEngine.increase_risk(
        db=db_session,
        device_id=sample_device.device_id,
        event_type="auth_failure",
        reason="Repeated invalid credentials",
    )

    assert updated is not None
    assert updated.risk_score > initial_score
    assert updated.risk_score == initial_score + 10.0


def test_decrease_risk(db_session, sample_device):
    """Test decreasing device risk score."""
    # First increase risk
    RiskEngine.increase_risk(
        db=db_session,
        device_id=sample_device.device_id,
        event_type="unauthorized_action",
        reason="Unauthorized endpoint call",
    )

    updated = RiskEngine.decrease_risk(
        db=db_session,
        device_id=sample_device.device_id,
        amount=15.0,
        reason="Periodic risk decay",
    )

    assert updated is not None
    assert updated.risk_score == 15.0  # (10 + 20) - 15 = 15


def test_reset_risk(db_session, sample_device):
    """Test resetting device risk to zero."""
    RiskEngine.increase_risk(
        db=db_session,
        device_id=sample_device.device_id,
        event_type="suspicious_behavior",
        reason="High throughput",
    )

    reset_device = RiskEngine.reset_risk(db=db_session, device_id=sample_device.device_id)

    assert reset_device is not None
    assert reset_device.risk_score == 0.0
    assert reset_device.risk_level == "LOW"


def test_check_thresholds(db_session, sample_device):
    """Test risk threshold evaluation for restrict/quarantine."""
    # Default score (10.0) -> None
    assert RiskEngine.check_thresholds(db_session, sample_device.device_id) is None

    # Increase to RESTRICT threshold (70+)
    RiskEngine.increase_risk(
        db=db_session,
        device_id=sample_device.device_id,
        event_type="custom",
        reason="Escalation",
        custom_delta=65.0,
    )
    assert RiskEngine.check_thresholds(db_session, sample_device.device_id) == "RESTRICT"

    # Increase to QUARANTINE threshold (90+)
    RiskEngine.increase_risk(
        db=db_session,
        device_id=sample_device.device_id,
        event_type="custom",
        reason="Critical anomaly",
        custom_delta=20.0,
    )
    assert RiskEngine.check_thresholds(db_session, sample_device.device_id) == "QUARANTINE"


def test_risk_history(db_session, sample_device):
    """Test recording and fetching risk history events."""
    RiskEngine.increase_risk(
        db=db_session,
        device_id=sample_device.device_id,
        event_type="auth_failure",
        reason="Failed login",
    )

    history = RiskEngine.get_risk_history(db_session, sample_device.device_id)
    assert len(history) == 1
    assert history[0].event_type == "auth_failure"
    assert history[0].reason == "Failed login"
