from typing import Any, Dict, Optional
from fastapi import HTTPException, status

class SIEMException(Exception):
    """Base exception for SIEM application."""
    
    def __init__(
        self,
        message: str,
        error_code: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)

class DatabaseError(SIEMException):
    """Database-related errors."""
    
    def __init__(
        self,
        message: str,
        error_code: str = "DATABASE_ERROR",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            details=details
        )

class AuthenticationError(SIEMException):
    """Authentication-related errors."""
    
    def __init__(
        self,
        message: str = "Authentication failed",
        error_code: str = "AUTHENTICATION_ERROR",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status.HTTP_401_UNAUTHORIZED,
            details=details
        )

class AuthorizationError(SIEMException):
    """Authorization-related errors."""
    
    def __init__(
        self,
        message: str = "Insufficient permissions",
        error_code: str = "AUTHORIZATION_ERROR",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status.HTTP_403_FORBIDDEN,
            details=details
        )

class ValidationError(SIEMException):
    """Data validation errors."""
    
    def __init__(
        self,
        message: str,
        error_code: str = "VALIDATION_ERROR",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details
        )

class ResourceNotFoundError(SIEMException):
    """Resource not found errors."""
    
    def __init__(
        self,
        message: str,
        error_code: str = "RESOURCE_NOT_FOUND",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status.HTTP_404_NOT_FOUND,
            details=details
        )

class RateLimitError(SIEMException):
    """Rate limiting errors."""
    
    def __init__(
        self,
        message: str = "Too many requests",
        error_code: str = "RATE_LIMIT_EXCEEDED",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details=details
        )

class OffensiveEngineError(SIEMException):
    """Offensive engine related errors."""
    
    def __init__(
        self,
        message: str,
        error_code: str = "OFFENSIVE_ENGINE_ERROR",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details
        )

class DefensiveEngineError(SIEMException):
    """Defensive engine related errors."""
    
    def __init__(
        self,
        message: str,
        error_code: str = "DEFENSIVE_ENGINE_ERROR",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details
        )

class MLPipelineError(SIEMException):
    """Machine learning pipeline errors."""
    
    def __init__(
        self,
        message: str,
        error_code: str = "ML_PIPELINE_ERROR",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details
        )

class ExternalServiceError(SIEMException):
    """External service integration errors."""
    
    def __init__(
        self,
        message: str,
        service_name: str,
        error_code: str = "EXTERNAL_SERVICE_ERROR",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        details = details or {}
        details["service_name"] = service_name
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status.HTTP_502_BAD_GATEWAY,
            details=details
        )

class WebSocketError(SIEMException):
    """WebSocket related errors."""
    
    def __init__(
        self,
        message: str,
        error_code: str = "WEBSOCKET_ERROR",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details
        ) 