"""
Tests for SQLAlchemy models creation and relationship integrity.
"""
from app.models.device import Device
from app.models.user import User


def test_user_creation(db_session):
    """Test creating and retrieving a User model."""
    user = User(
        username="secops",
        email="secops@zerotrust.local",
        hashed_password="hashed_secret_string",
        role="operator",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    fetched = db_session.query(User).filter(User.username == "secops").first()
    assert fetched is not None
    assert fetched.email == "secops@zerotrust.local"
    assert fetched.role == "operator"


def test_device_creation(db_session):
    """Test creating and retrieving a Device model."""
    device = Device(
        device_id="DEV-2002",
        name="Smart Sensor Node",
        device_type="Sensor",
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.150",
        firmware_version="2.1.0",
        status="active",
        auth_status="authenticated",
        risk_score=0.0,
        risk_level="LOW",
    )
    db_session.add(device)
    db_session.commit()

    fetched = db_session.query(Device).filter(Device.device_id == "DEV-2002").first()
    assert fetched is not None
    assert fetched.name == "Smart Sensor Node"
    assert fetched.status == "active"
