"""
Tests for security utilities (password hashing and JWT token management).
"""
from datetime import timedelta
from app.security.password import hash_password, verify_password
from app.security.jwt_handler import create_access_token, decode_access_token


def test_password_hashing():
    """Test hashing and verification of passwords."""
    raw_pass = "SecureP@ssword2024"
    hashed = hash_password(raw_pass)

    assert hashed != raw_pass
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_jwt_token_flow():
    """Test JWT creation and decoding."""
    payload_data = {"sub": "testuser", "role": "admin"}
    token = create_access_token(data=payload_data, expires_delta=timedelta(minutes=15))

    assert isinstance(token, str)
    decoded = decode_access_token(token)

    assert decoded is not None
    assert decoded["sub"] == "testuser"
    assert decoded["role"] == "admin"
    assert "exp" in decoded


def test_invalid_jwt_token():
    """Test decoding an invalid token returns None."""
    assert decode_access_token("invalid.token.payload") is None
