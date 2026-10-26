"""
Application configuration loaded from environment variables.
"""
from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    """Application settings loaded from .env file."""

    # Database
    DATABASE_URL: str = "sqlite:///./zero_trust_iot.db"

    # Security
    SECRET_KEY: str = "change-this-to-a-random-secret-key-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480

    # Default Admin
    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_PASSWORD: str = "ZeroTrust@2024!"
    DEFAULT_ADMIN_EMAIL: str = "admin@zerotrust.local"

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # Risk Engine
    RISK_QUARANTINE_THRESHOLD: int = 90
    RISK_RESTRICT_THRESHOLD: int = 70
    RISK_DECAY_RATE: float = 1.0
    RISK_DECAY_INTERVAL_SECONDS: int = 60

    # Simulator
    SIMULATOR_TELEMETRY_INTERVAL: int = 5
    SIMULATOR_ENABLED: bool = True

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    model_config = {
        "env_file": os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()
