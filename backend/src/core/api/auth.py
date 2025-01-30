from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from ...data.db import get_db
from ...data.repositories.user import user_repository, role_repository
from ...data.models.user import User
from ...utils.security import (
    Token,
    verify_password,
    create_access_token,
    generate_mfa_secret,
    verify_mfa_token,
    get_mfa_uri
)
from ..auth import (
    get_current_user,
    get_current_active_user,
    get_current_superuser
)
from ..exceptions import AuthenticationError
from ...utils.logging import LoggerMixin

router = APIRouter()
logger = LoggerMixin()

# Request/Response Models
class UserCreate(BaseModel):
    """User creation model."""
    username: str
    email: EmailStr
    full_name: str
    password: str
    role_name: str = "user"

class UserLogin(BaseModel):
    """User login model."""
    username: str
    password: str
    mfa_token: Optional[str] = None

class UserResponse(BaseModel):
    """User response model."""
    username: str
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    is_superuser: bool
    mfa_enabled: bool

class MFAResponse(BaseModel):
    """MFA response model."""
    secret: str
    uri: str

@router.post("/register", response_model=UserResponse)
async def register(
    user_in: UserCreate,
    session: AsyncSession = Depends(get_db)
) -> User:
    """Register new user."""
    try:
        # Check if username exists
        if await user_repository.get_by_username(session, user_in.username):
            raise AuthenticationError("Username already registered")
        
        # Check if email exists
        if await user_repository.get_by_email(session, user_in.email):
            raise AuthenticationError("Email already registered")
        
        # Get role
        role = await role_repository.get_by_name(session, user_in.role_name)
        if not role:
            raise AuthenticationError("Invalid role")
        
        # Create user
        user = await user_repository.create(
            session,
            {
                "username": user_in.username,
                "email": user_in.email,
                "full_name": user_in.full_name,
                "role_id": role.id,
                "hashed_password": get_password_hash(user_in.password)
            }
        )
        
        await session.commit()
        return user
    except Exception as e:
        await session.rollback()
        raise

@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_db)
) -> Token:
    """Login user."""
    try:
        # Get user
        user = await user_repository.get_by_username(session, form_data.username)
        if not user:
            raise AuthenticationError("Incorrect username or password")
        
        # Verify password
        if not verify_password(form_data.password, user.hashed_password):
            await user_repository.update(
                session,
                db_obj=user,
                obj_in={"failed_login_attempts": user.failed_login_attempts + 1}
            )
            await session.commit()
            raise AuthenticationError("Incorrect username or password")
        
        # Check if account is locked
        if user.failed_login_attempts >= 5:
            raise AuthenticationError("Account is locked. Please reset your password")
        
        # Check if MFA is required
        if user.mfa_enabled and not form_data.mfa_token:
            raise AuthenticationError("MFA token required")
        
        # Verify MFA token
        if user.mfa_enabled:
            if not verify_mfa_token(user.mfa_secret, form_data.mfa_token):
                raise AuthenticationError("Invalid MFA token")
        
        # Update user
        await user_repository.update(
            session,
            db_obj=user,
            obj_in={
                "last_login": datetime.utcnow(),
                "failed_login_attempts": 0
            }
        )
        await session.commit()
        
        # Create access token
        return create_access_token(
            data={
                "sub": user.username,
                "scopes": user.role.permissions.get("scopes", [])
            }
        )
    except Exception as e:
        await session.rollback()
        raise

@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db)
) -> dict:
    """Logout user."""
    try:
        # Update last login
        await user_repository.update(
            session,
            db_obj=current_user,
            obj_in={"last_login": datetime.utcnow()}
        )
        await session.commit()
        return {"message": "Successfully logged out"}
    except Exception as e:
        await session.rollback()
        raise

@router.post("/mfa/enable", response_model=MFAResponse)
async def enable_mfa(
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db)
) -> dict:
    """Enable MFA for user."""
    try:
        # Generate MFA secret
        secret = generate_mfa_secret()
        uri = get_mfa_uri(secret, current_user.username)
        
        # Update user
        await user_repository.update(
            session,
            db_obj=current_user,
            obj_in={
                "mfa_secret": secret,
                "mfa_enabled": True
            }
        )
        await session.commit()
        
        return {
            "secret": secret,
            "uri": uri
        }
    except Exception as e:
        await session.rollback()
        raise

@router.post("/mfa/disable")
async def disable_mfa(
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db)
) -> dict:
    """Disable MFA for user."""
    try:
        # Update user
        await user_repository.update(
            session,
            db_obj=current_user,
            obj_in={
                "mfa_secret": None,
                "mfa_enabled": False
            }
        )
        await session.commit()
        
        return {"message": "MFA disabled"}
    except Exception as e:
        await session.rollback()
        raise

@router.post("/password/change")
async def change_password(
    old_password: str,
    new_password: str,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db)
) -> dict:
    """Change user password."""
    try:
        # Verify old password
        if not verify_password(old_password, current_user.hashed_password):
            raise AuthenticationError("Incorrect password")
        
        # Update password
        await user_repository.update(
            session,
            db_obj=current_user,
            obj_in={
                "hashed_password": get_password_hash(new_password),
                "password_changed_at": datetime.utcnow(),
                "require_password_change": False
            }
        )
        await session.commit()
        
        return {"message": "Password changed"}
    except Exception as e:
        await session.rollback()
        raise

@router.post("/password/reset")
async def reset_password(
    username: str,
    session: AsyncSession = Depends(get_db)
) -> dict:
    """Reset user password."""
    try:
        # Get user
        user = await user_repository.get_by_username(session, username)
        if not user:
            raise AuthenticationError("User not found")
        
        # Generate temporary password
        temp_password = secrets.token_urlsafe(12)
        
        # Update user
        await user_repository.update(
            session,
            db_obj=user,
            obj_in={
                "hashed_password": get_password_hash(temp_password),
                "require_password_change": True,
                "failed_login_attempts": 0
            }
        )
        await session.commit()
        
        # TODO: Send password reset email
        
        return {"message": "Password reset email sent"}
    except Exception as e:
        await session.rollback()
        raise

@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Get current user."""
    return current_user

@router.get("/users", response_model=list[UserResponse])
async def get_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_superuser),
    session: AsyncSession = Depends(get_db)
) -> list[User]:
    """Get all users."""
    return await user_repository.get_all(session, skip=skip, limit=limit) 