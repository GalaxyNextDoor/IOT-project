"""
Tests for main FastAPI application routes (/ and /health).
"""


def test_root_endpoint(client):
    """Test the root API endpoint returns status online."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "system" in data
    assert "version" in data


def test_health_check(client):
    """Test the /health endpoint returns healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_device_registration_and_telemetry_flow(client):
    """Test registering a device, authenticating, and sending telemetry."""
    # 1. Register device
    reg_resp = client.post(
        "/api/v1/devices/register",
        json={
            "device_id": "RPI-DEMO-01",
            "name": "Raspberry Pi 4 Model B",
            "device_type": "single_board_computer",
            "manufacturer": "Raspberry Pi Ltd",
            "firmware_version": "1.4",
            "ip_address": "192.168.1.88",
            "mac_address": "DC:A6:32:01:02:03",
        },
    )
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert reg_data["status"] == "success"
    api_key = reg_data["api_key"]

    # 2. Authenticate device
    auth_resp = client.post(
        "/api/v1/devices/authenticate",
        headers={"X-Device-ID": "RPI-DEMO-01", "X-API-Key": api_key},
    )
    assert auth_resp.status_code == 200
    assert auth_resp.json()["authenticated"] is True

    # 3. Send telemetry
    telem_resp = client.post(
        "/api/v1/telemetry",
        headers={"X-Device-ID": "RPI-DEMO-01", "X-API-Key": api_key},
        json={
            "device_id": "RPI-DEMO-01",
            "data_type": "sensor_reading",
            "metrics": {"cpu_temp": 42.5, "memory_usage": 34.2},
            "is_anomalous": False,
        },
    )
    assert telem_resp.status_code == 200
    assert telem_resp.json()["status"] == "accepted"

