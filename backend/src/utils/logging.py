import json
import logging
import logging.config
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import sentry_sdk
from pythonjsonlogger import jsonlogger
from sentry_sdk.integrations.logging import LoggingIntegration

from ..core.settings import get_settings

settings = get_settings()

class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with additional fields."""
    
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]) -> None:
        """Add custom fields to the log record."""
        super().add_fields(log_record, record, message_dict)
        
        # Add timestamp
        log_record['timestamp'] = datetime.utcnow().isoformat()
        log_record['level'] = record.levelname
        log_record['logger'] = record.name
        
        # Add correlation ID if available
        if hasattr(record, 'correlation_id'):
            log_record['correlation_id'] = record.correlation_id
        
        # Add request information if available
        if hasattr(record, 'request_id'):
            log_record['request_id'] = record.request_id
        if hasattr(record, 'user_id'):
            log_record['user_id'] = record.user_id
        
        # Add exception information if available
        if record.exc_info:
            log_record['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }

def setup_logging(
    level: Optional[str] = None,
    enable_sentry: bool = True,
    service_name: str = "siem-backend"
) -> None:
    """Configure application-wide logging.
    
    Args:
        level: Log level (defaults to settings.LOG_LEVEL)
        enable_sentry: Whether to enable Sentry integration
        service_name: Name of the service for logging context
    """
    log_level = level or settings.LOG_LEVEL
    
    # Create custom JSON formatter
    formatter = CustomJsonFormatter(
        '%(timestamp)s %(level)s %(name)s %(message)s'
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Initialize Sentry if enabled and DSN is configured
    if enable_sentry and settings.SENTRY_DSN:
        sentry_logging = LoggingIntegration(
            level=logging.INFO,
            event_level=logging.ERROR
        )
        
        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            traces_sample_rate=1.0,
            environment=settings.ENVIRONMENT,
            integrations=[sentry_logging],
            release=service_name
        )
    
    # Disable other loggers
    logging.getLogger('uvicorn.access').handlers = []
    
    logger = logging.getLogger(__name__)
    logger.info(
        "Logging configured",
        extra={
            'service': service_name,
            'log_level': log_level,
            'sentry_enabled': enable_sentry and bool(settings.SENTRY_DSN)
        }
    )

class LoggerMixin:
    """Mixin to add logging capabilities to a class."""
    
    @property
    def logger(self) -> logging.Logger:
        """Get logger for the class."""
        if not hasattr(self, '_logger'):
            self._logger = logging.getLogger(self.__class__.__name__)
        return self._logger
    
    def log_info(self, message: str, **kwargs: Any) -> None:
        """Log an info message with additional context."""
        self.logger.info(message, extra=self._prepare_extra(kwargs))
    
    def log_error(self, message: str, error: Optional[Exception] = None, **kwargs: Any) -> None:
        """Log an error message with additional context."""
        extra = self._prepare_extra(kwargs)
        if error:
            extra['error'] = {
                'type': error.__class__.__name__,
                'message': str(error)
            }
        self.logger.error(message, extra=extra, exc_info=bool(error))
    
    def log_warning(self, message: str, **kwargs: Any) -> None:
        """Log a warning message with additional context."""
        self.logger.warning(message, extra=self._prepare_extra(kwargs))
    
    def log_debug(self, message: str, **kwargs: Any) -> None:
        """Log a debug message with additional context."""
        self.logger.debug(message, extra=self._prepare_extra(kwargs))
    
    def _prepare_extra(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare extra fields for logging."""
        extra = {}
        
        # Add class context
        extra['class'] = self.__class__.__name__
        
        # Add correlation ID if available
        if hasattr(self, 'correlation_id'):
            extra['correlation_id'] = self.correlation_id
        
        # Add custom fields
        extra.update(kwargs)
        
        return extra 