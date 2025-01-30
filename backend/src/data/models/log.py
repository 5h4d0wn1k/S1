from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from uuid import UUID

from pydantic import Field, validator

from .base import BaseModelWithMetadata

class LogType(str, Enum):
    """Log type enumeration."""
    SYSLOG = "syslog"
    WINDOWS = "windows"
    LINUX = "linux"
    NETWORK = "network"
    APPLICATION = "application"
    SECURITY = "security"
    AUDIT = "audit"
    CUSTOM = "custom"

class LogLevel(str, Enum):
    """Log level enumeration."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class LogSourceType(str, Enum):
    """Log source type enumeration."""
    SYSLOG = "syslog"
    FILE = "file"
    API = "api"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    CUSTOM = "custom"

class LogSourceStatus(str, Enum):
    """Log source status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"

class LogSource(BaseModelWithMetadata):
    """Log source model."""
    name: str
    type: LogSourceType
    status: LogSourceStatus = LogSourceStatus.PENDING
    configuration: Dict[str, Any]
    last_ingestion_time: Optional[datetime] = None
    error_count: int = 0
    error_message: Optional[str] = None
    
    @validator("configuration")
    def validate_configuration(cls, v, values):
        """Validate source configuration based on type."""
        source_type = values.get("type")
        if not source_type:
            return v
            
        required_fields = {
            LogSourceType.SYSLOG: ["host", "port", "protocol"],
            LogSourceType.FILE: ["path", "format"],
            LogSourceType.API: ["url", "method", "auth"],
            LogSourceType.AWS: ["region", "access_key_id", "secret_access_key"],
            LogSourceType.AZURE: ["tenant_id", "client_id", "client_secret"],
            LogSourceType.GCP: ["project_id", "credentials"]
        }
        
        if source_type in required_fields:
            for field in required_fields[source_type]:
                if field not in v:
                    raise ValueError(f"Missing required field for {source_type}: {field}")
        
        return v

class LogEntry(BaseModelWithMetadata):
    """Log entry model."""
    source_id: UUID
    log_type: LogType
    level: LogLevel = LogLevel.INFO
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    message: str
    raw_data: Dict[str, Any]
    parsed_data: Optional[Dict[str, Any]] = None
    host: Optional[str] = None
    ip_address: Optional[str] = None
    process: Optional[str] = None
    user: Optional[str] = None
    correlation_id: Optional[str] = None
    enriched: bool = False
    enrichment_data: Optional[Dict[str, Any]] = None
    
    @validator("parsed_data", always=True)
    def set_parsed_data(cls, v, values):
        """Set parsed data if not provided."""
        if v is None and "raw_data" in values:
            # Basic parsing based on log type
            log_type = values.get("log_type")
            if log_type == LogType.SYSLOG:
                return cls._parse_syslog(values["raw_data"])
            elif log_type == LogType.WINDOWS:
                return cls._parse_windows(values["raw_data"])
            # Add more parsing logic for other log types
        return v
    
    @staticmethod
    def _parse_syslog(raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse syslog format."""
        parsed = {}
        if "facility" in raw_data:
            parsed["facility"] = raw_data["facility"]
        if "severity" in raw_data:
            parsed["severity"] = raw_data["severity"]
        if "program" in raw_data:
            parsed["program"] = raw_data["program"]
        return parsed
    
    @staticmethod
    def _parse_windows(raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Windows event log format."""
        parsed = {}
        if "EventID" in raw_data:
            parsed["event_id"] = raw_data["EventID"]
        if "Channel" in raw_data:
            parsed["channel"] = raw_data["Channel"]
        if "Provider" in raw_data:
            parsed["provider"] = raw_data["Provider"]
        return parsed

class LogBatch(BaseModel):
    """Log batch model for bulk operations."""
    source_id: UUID
    entries: list[LogEntry]
    batch_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    processed: bool = False
    error_count: int = 0
    success_count: int = 0

class LogSourceMetrics(BaseModel):
    """Log source metrics model."""
    source_id: UUID
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    logs_per_second: float
    bytes_per_second: float
    error_rate: float
    average_processing_time: float
    queue_size: int
    batch_success_rate: float 