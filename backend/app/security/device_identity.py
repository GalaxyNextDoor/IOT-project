"""
Device identity and credential management abstractions.
Designed to support API keys now and certificates (mTLS) later.
"""
import secrets
import hashlib
from typing import Optional


def generate_api_key() -> str:
    """Generate a secure API key for device authentication."""
    return f"zt_{secrets.token_urlsafe(32)}"


def hash_api_key(api_key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def verify_api_key(api_key: str, hashed_key: str) -> bool:
    """Verify an API key against its hash."""
    return hash_api_key(api_key) == hashed_key


def generate_certificate_fingerprint(cert_pem: Optional[str] = None) -> str:
    """
    Generate a certificate fingerprint.
    For the prototype, generates a mock fingerprint.
    When real certificates are used, this will hash the DER-encoded cert.
    """
    if cert_pem:
        return hashlib.sha256(cert_pem.encode()).hexdigest()
    # Mock fingerprint for simulation
    return hashlib.sha256(secrets.token_bytes(32)).hexdigest()
