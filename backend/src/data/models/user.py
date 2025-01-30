from datetime import datetime, timedelta
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import String, Boolean, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from .base import Base
from ...utils.security import get_password_hash

class Role(Base):
    """User role model."""
    
    name: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(200))
    permissions: Mapped[dict] = mapped_column(JSON, default=dict)
    
    # Relationships
    users: Mapped[List["User"]] = relationship(back_populates="role")

class User(Base):
    """User model."""
    
    # Basic info
    uuid: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        default=uuid4,
        unique=True,
        index=True
    )
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(100))
    
    # Authentication
    hashed_password: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Security
    failed_login_attempts: Mapped[int] = mapped_column(default=0)
    last_login: Mapped[Optional[datetime]] = mapped_column()
    password_changed_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    require_password_change: Mapped[bool] = mapped_column(default=False)
    
    # MFA
    mfa_enabled: Mapped[bool] = mapped_column(default=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(32))
    
    # Preferences
    preferences: Mapped[dict] = mapped_column(JSON, default=dict)
    
    # API access
    api_key: Mapped[Optional[str]] = mapped_column(String(64), unique=True)
    api_key_expires_at: Mapped[Optional[datetime]] = mapped_column()
    
    # Relationships
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"))
    role: Mapped[Role] = relationship(back_populates="users")
    
    def set_password(self, password: str) -> None:
        """Set user password."""
        self.hashed_password = get_password_hash(password)
        self.password_changed_at = datetime.utcnow()
        self.require_password_change = False
    
    def update_last_login(self) -> None:
        """Update last login timestamp."""
        self.last_login = datetime.utcnow()
        self.failed_login_attempts = 0
    
    def increment_failed_login(self) -> None:
        """Increment failed login attempts."""
        self.failed_login_attempts += 1
    
    def reset_failed_login(self) -> None:
        """Reset failed login attempts."""
        self.failed_login_attempts = 0
    
    def generate_api_key(self, expires_in_days: int = 30) -> str:
        """Generate new API key."""
        self.api_key = uuid4().hex
        self.api_key_expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        return self.api_key
    
    def revoke_api_key(self) -> None:
        """Revoke API key."""
        self.api_key = None
        self.api_key_expires_at = None
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        if self.is_superuser:
            return True
        return permission in self.role.permissions.get("permissions", []) 