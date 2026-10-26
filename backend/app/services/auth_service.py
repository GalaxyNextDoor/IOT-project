"""
Admin user authentication service.
Handles login, token generation, and user management.
"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.models.user import User
from app.security.password import hash_password, verify_password
from app.security.jwt_handler import create_access_token
from app.services.audit_service import AuditService


class AuthService:
    """Handles admin user authentication."""

    @staticmethod
    def authenticate_user(db: Session, username: str, password: str) -> Optional[dict]:
        """
        Authenticate an admin user. Returns token data or None.
        """
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.hashed_password):
            AuditService.log_event(
                db=db,
                event_type="ADMIN_LOGIN_FAILED",
                severity="MEDIUM",
                description=f"Failed login attempt for username: {username}",
            )
            return None

        if not user.is_active:
            return None

        # Update last login
        user.last_login = datetime.now(timezone.utc)
        db.commit()

        # Create token
        token = create_access_token(data={"sub": user.username, "role": user.role, "user_id": user.id})

        AuditService.log_event(
            db=db,
            event_type="ADMIN_LOGIN",
            severity="INFO",
            description=f"Admin '{username}' logged in",
            user_id=user.id,
        )

        return {
            "access_token": token,
            "token_type": "bearer",
            "username": user.username,
            "role": user.role,
        }

    @staticmethod
    def get_user_by_username(db: Session, username: str) -> Optional[User]:
        """Get a user by username."""
        return db.query(User).filter(User.username == username).first()

    @staticmethod
    def create_user(db: Session, username: str, email: str, password: str, role: str = "admin") -> User:
        """Create a new admin user."""
        user = User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            role=role,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
