import time
from typing import Any, Dict, List

from fastapi import FastAPI, Request, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded

from .core.exceptions import SIEMException, RateLimitError
from .core.settings import get_settings
from .utils.logging import LoggerMixin, setup_logging
from .data.pipeline_manager import pipeline_manager
from .core.websocket import ws_manager
from .core.monitoring import (
    setup_monitoring,
    metrics_endpoint,
    REQUESTS_TOTAL,
    REQUEST_DURATION,
    update_websocket_connections
)

settings = get_settings()
logger = LoggerMixin().get_logger()

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware for collecting request metrics."""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Any:
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        
        # Record metrics
        REQUESTS_TOTAL.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code
        ).inc()
        
        REQUEST_DURATION.labels(
            method=request.method,
            endpoint=request.url.path
        ).observe(duration)
        
        return response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware for adding security headers."""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Any:
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self' ws: wss:;"
        )
        
        return response

class RequestLoggingMiddleware(BaseHTTPMiddleware, LoggerMixin):
    """Middleware for request logging."""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Any:
        start_time = time.time()
        
        # Log request
        self.log_info(
            "Incoming request",
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        try:
            response = await call_next(request)
            duration = time.time() - start_time
            
            # Log response
            self.log_info(
                "Request completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration=f"{duration:.3f}s"
            )
            
            return response
        except Exception as e:
            duration = time.time() - start_time
            self.log_error(
                "Request failed",
                error=e,
                method=request.method,
                path=request.url.path,
                duration=f"{duration:.3f}s"
            )
            raise

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    
    # Initialize logging
    setup_logging()
    
    app = FastAPI(
        title=settings.PROJECT_NAME,
        description="Next-generation SIEM with offensive and defensive capabilities",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json"
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.BACKEND_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Security middleware
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", settings.SERVER_HOST]
    )
    
    # Rate limiting middleware
    if settings.RATE_LIMIT_ENABLED:
        app.state.limiter = limiter
        app.add_middleware(SlowAPIMiddleware)
    
    # Custom middleware
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    
    # Exception handlers
    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": True,
                "code": "RATE_LIMIT_EXCEEDED",
                "message": "Too many requests",
                "path": request.url.path
            }
        )
    
    @app.exception_handler(SIEMException)
    async def siem_exception_handler(request: Request, exc: SIEMException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": True,
                "code": exc.error_code,
                "message": exc.message,
                "details": exc.details,
                "path": request.url.path
            }
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": True,
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "path": request.url.path
            }
        )
    
    # Startup event
    @app.on_event("startup")
    async def startup_event():
        """Initialize resources on startup."""
        try:
            # Initialize monitoring
            setup_monitoring(app)
            
            # Start WebSocket manager
            await ws_manager.start()
            
            # Start data pipeline
            await pipeline_manager.start()
            
            logger.info("Application started successfully")
        except Exception as e:
            logger.error("Failed to start application", error=e)
            raise
    
    # Shutdown event
    @app.on_event("shutdown")
    async def shutdown_event():
        """Cleanup resources on shutdown."""
        try:
            # Stop WebSocket manager
            await ws_manager.stop()
            
            # Stop data pipeline
            await pipeline_manager.stop()
            
            logger.info("Application shutdown successfully")
        except Exception as e:
            logger.error("Failed to shutdown application", error=e)
            raise
    
    # Health check endpoint
    @app.get("/health", dependencies=[Depends(limiter.limit("10/minute"))])
    async def health_check() -> Dict[str, str]:
        return {"status": "healthy"}
    
    # Metrics endpoint
    if settings.PROMETHEUS_ENABLED:
        app.add_route("/metrics", metrics_endpoint)
    
    # Import and include API routers
    from .core.api import (
        alerts,
        auth,
        dashboards,
        incidents,
        offensive,
        defensive,
        settings,
        websocket
    )
    
    # API routes
    app.include_router(
        auth.router,
        prefix=f"{settings.API_V1_STR}/auth",
        tags=["Authentication"]
    )
    app.include_router(
        alerts.router,
        prefix=f"{settings.API_V1_STR}/alerts",
        tags=["Alerts"]
    )
    app.include_router(
        dashboards.router,
        prefix=f"{settings.API_V1_STR}/dashboards",
        tags=["Dashboards"]
    )
    app.include_router(
        incidents.router,
        prefix=f"{settings.API_V1_STR}/incidents",
        tags=["Incidents"]
    )
    app.include_router(
        offensive.router,
        prefix=f"{settings.API_V1_STR}/offensive",
        tags=["Offensive Security"]
    )
    app.include_router(
        defensive.router,
        prefix=f"{settings.API_V1_STR}/defensive",
        tags=["Defensive Security"]
    )
    app.include_router(
        settings.router,
        prefix=f"{settings.API_V1_STR}/settings",
        tags=["Settings"]
    )
    
    # WebSocket routes
    app.include_router(
        websocket.router,
        prefix=f"{settings.API_V1_STR}/ws",
        tags=["WebSocket"]
    )
    
    return app

app = create_app() 