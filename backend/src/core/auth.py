from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from .exceptions import AuthenticationError, AuthorizationError
from .settings import get_settings
from ..utils.logging import LoggerMixin
from ..data.db import get_db
from ..data.repositories.user import user_repository
from ..data.models.user import User
from ..utils.security import decode_token, verify_api_key

settings = get_settings()

# Models
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class TokenData(BaseModel):
    username: str
    role: str
    permissions: list[str]

class User(BaseModel):
    username: str
    email: str
    role: str
    permissions: list[str]
    disabled: bool = False

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"/api/v1/auth/login",
    scopes={
        "user": "Basic user access",
        "admin": "Administrator access",
        "analyst": "Security analyst access",
        "engineer": "Security engineer access"
    }
)

api_key_header = APIKeyHeader(name="X-API-Key")

class AuthManager(LoggerMixin):
    """Handles authentication and authorization."""
    
    def __init__(self) -> None:
        self.algorithm = settings.ALGORITHM
        self.secret_key = settings.SECRET_KEY
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            self.log_error("Password verification failed", e)
            return False
    
    def get_password_hash(self, password: str) -> str:
        """Generate password hash."""
        return pwd_context.hash(password)
    
    def create_access_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a JWT access token."""
        try:
            to_encode = data.copy()
            
            if expires_delta:
                expire = datetime.utcnow() + expires_delta
            else:
                expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
            
            to_encode.update({
                "exp": expire,
                "iat": datetime.utcnow(),
                "type": "access"
            })
            
            encoded_jwt = jwt.encode(
                to_encode,
                self.secret_key,
                algorithm=self.algorithm
            )
            
            self.log_info(
                "Access token created",
                username=data.get("sub"),
                expires=expire.isoformat()
            )
            
            return encoded_jwt
        except Exception as e:
            self.log_error("Token creation failed", e)
            raise AuthenticationError("Could not create access token")
    
    async def get_current_user(
        self,
        token: str = Depends(oauth2_scheme),
        session: AsyncSession = Depends(get_db)
    ) -> User:
        """Get the current user from a JWT token."""
        try:
            token_data = decode_token(token)
            user = await user_repository.get_by_username(session, token_data.sub)
            
            if not user:
                raise AuthenticationError("User not found")
            if not user.is_active:
                raise AuthenticationError("User is inactive")
            
            return user
        except Exception as e:
            self.log_error("Token validation failed", e)
            raise AuthenticationError("Could not validate credentials")
    
    async def get_current_active_user(
        self,
        current_user: User = Depends(get_current_user)
    ) -> User:
        """Get the current active user."""
        if not current_user.is_active:
            raise AuthenticationError("Inactive user")
        return current_user
    
    def check_permissions(
        self,
        user: User,
        required_permissions: Union[str, list[str]]
    ) -> bool:
        """Check if a user has the required permissions."""
        if isinstance(required_permissions, str):
            required_permissions = [required_permissions]
        
        # Superadmin role has all permissions
        if user.role == "superadmin":
            return True
        
        return all(perm in user.permissions for perm in required_permissions)

# Dependency for requiring specific permissions
def requires_permissions(permissions: Union[str, list[str]]):
    """Decorator to require specific permissions for an endpoint."""
    async def permission_checker(
        current_user: User = Depends(auth_manager.get_current_active_user)
    ) -> None:
        if not auth_manager.check_permissions(current_user, permissions):
            raise AuthorizationError(
                "Insufficient permissions",
                details={"required_permissions": permissions}
            )
    return permission_checker

# Global auth manager instance
auth_manager = AuthManager()

async def get_current_superuser(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current superuser."""
    if not current_user.is_superuser:
        raise AuthenticationError("Not enough privileges")
    return current_user

async def get_api_key_user(
    api_key: str = Depends(api_key_header),
    session: AsyncSession = Depends(get_db)
) -> User:
    """Get user from API key."""
    try:
        user = await user_repository.get_by_api_key(session, api_key)
        
        if not user:
            raise AuthenticationError("Invalid API key")
        if not user.is_active:
            raise AuthenticationError("User is inactive")
        
        return user
    except Exception as e:
        raise AuthenticationError("Could not validate API key")

def check_permission(permission: str):
    """Check if user has permission."""
    async def permission_checker(
        current_user: User = Depends(get_current_user)
    ) -> None:
        if not current_user.has_permission(permission):
            raise AuthenticationError(
                f"Not enough privileges. Required permission: {permission}"
            )
    return permission_checker

def check_scope(scope: str):
    """Check if user has scope."""
    async def scope_checker(
        current_user: User = Depends(get_current_user)
    ) -> None:
        if scope not in current_user.role.permissions.get("scopes", []):
            raise AuthenticationError(
                f"Not enough privileges. Required scope: {scope}"
            )
    return scope_checker

def get_optional_user(
    token: Optional[str] = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Get optional user from token."""
    try:
        if not token:
            return None
            
        token_data = decode_token(token)
        user = await user_repository.get_by_username(session, token_data.sub)
        
        if not user or not user.is_active:
            return None
            
        return user
    except Exception:
        return None

def get_optional_api_key_user(
    api_key: Optional[str] = Depends(api_key_header),
    session: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Get optional user from API key."""
    try:
        if not api_key:
            return None
            
        user = await user_repository.get_by_api_key(session, api_key)
        
        if not user or not user.is_active:
            return None
            
        return user
    except Exception:
        return None 