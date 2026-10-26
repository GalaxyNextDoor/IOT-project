"""
Pytest configuration and global fixtures.
Sets up an in-memory SQLite database for test isolation.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.device import Device
from app.models.user import User
from app.security.password import hash_password

# Use in-memory SQLite for test isolation
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    """Create a fresh in-memory database for each test."""
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    """FastAPI TestClient with overridden get_db dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def sample_user(db_session):
    """Create a sample admin user in the test database."""
    user = User(
        username="testadmin",
        email="testadmin@zerotrust.local",
        hashed_password=hash_password("Password123!"),
        role="admin",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def sample_device(db_session):
    """Create a sample IoT device in the test database."""
    device = Device(
        device_id="DEV-1001",
        name="Test Gateway",
        device_type="Gateway",
        mac_address="AA:BB:CC:DD:EE:FF",
        ip_address="192.168.1.100",
        firmware_version="1.0.0",
        status="active",
        auth_status="authenticated",
        risk_score=10.0,
        risk_level="LOW",
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device
