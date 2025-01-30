from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union

from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from ..core.settings import get_settings

settings = get_settings()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Token(BaseModel):
    """Token model."""
    access_token: str
    token_type: str
    expires_at: datetime

class TokenData(BaseModel):
    """Token data model."""
    sub: str
    exp: datetime
    scopes: list[str] = []

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error("Failed to verify password", error=e)
        return False

def get_password_hash(password: str) -> str:
    """Get password hash."""
    try:
        return pwd_context.hash(password)
    except Exception as e:
        logger.error("Failed to hash password", error=e)
        raise

def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> Token:
    """Create access token."""
    try:
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow()
        })
        
        encoded_jwt = jwt.encode(
            to_encode,
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )
        
        return Token(
            access_token=encoded_jwt,
            token_type="bearer",
            expires_at=expire
        )
    except Exception as e:
        logger.error("Failed to create access token", error=e)
        raise

def decode_token(token: str) -> TokenData:
    """Decode token."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        
        return TokenData(
            sub=payload["sub"],
            exp=datetime.fromtimestamp(payload["exp"]),
            scopes=payload.get("scopes", [])
        )
    except jwt.JWTError as e:
        logger.error("Failed to decode token", error=e)
        raise
    except Exception as e:
        logger.error("Unexpected error decoding token", error=e)
        raise

def generate_api_key() -> str:
    """Generate API key."""
    try:
        return secrets.token_hex(32)
    except Exception as e:
        logger.error("Failed to generate API key", error=e)
        raise

def verify_api_key(api_key: str, stored_key: str) -> bool:
    """Verify API key."""
    try:
        return secrets.compare_digest(api_key, stored_key)
    except Exception as e:
        logger.error("Failed to verify API key", error=e)
        return False

def generate_mfa_secret() -> str:
    """Generate MFA secret."""
    try:
        return pyotp.random_base32()
    except Exception as e:
        logger.error("Failed to generate MFA secret", error=e)
        raise

def verify_mfa_token(secret: str, token: str) -> bool:
    """Verify MFA token."""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token)
    except Exception as e:
        logger.error("Failed to verify MFA token", error=e)
        return False

def get_mfa_uri(secret: str, username: str) -> str:
    """Get MFA URI for QR code."""
    try:
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            username,
            issuer_name=settings.PROJECT_NAME
        )
    except Exception as e:
        logger.error("Failed to get MFA URI", error=e)
        raise 