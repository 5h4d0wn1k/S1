from datetime import datetime, time
from enum import Enum
from typing import Optional, Dict, Any, List
from uuid import UUID

from pydantic import Field, validator

from .base import BaseModelWithMetadata

class ReportType(str, Enum):
    """Report type enumeration."""
    INCIDENT = "incident"
    ALERT = "alert"
    COMPLIANCE = "compliance"
    METRICS = "metrics"
    AUDIT = "audit"
    EXECUTIVE = "executive"
    CUSTOM = "custom"

class ReportFormat(str, Enum):
    """Report format enumeration."""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    EXCEL = "excel"

class ReportStatus(str, Enum):
    """Report status enumeration."""
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"
    ARCHIVED = "archived"

class ReportScheduleFrequency(str, Enum):
    """Report schedule frequency enumeration."""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"

class ReportTemplate(BaseModelWithMetadata):
    """Report template model."""
    name: str
    report_type: ReportType
    formats: List[ReportFormat]
    content: Dict[str, Any]
    parameters: Dict[str, Any]
    version: str = "1.0.0"
    custom_styles: Optional[Dict[str, Any]] = None
    custom_scripts: Optional[Dict[str, Any]] = None
    
    @validator("content")
    def validate_content(cls, v, values):
        """Validate template content based on type."""
        report_type = values.get("report_type")
        if not report_type:
            return v
            
        required_sections = {
            ReportType.INCIDENT: ["summary", "timeline", "impact", "recommendations"],
            ReportType.ALERT: ["summary", "details", "indicators", "analysis"],
            ReportType.COMPLIANCE: ["overview", "controls", "findings", "remediation"],
            ReportType.METRICS: ["summary", "metrics", "trends", "analysis"],
            ReportType.AUDIT: ["scope", "findings", "evidence", "conclusion"],
            ReportType.EXECUTIVE: ["summary", "highlights", "risks", "recommendations"]
        }
        
        if report_type in required_sections and report_type != ReportType.CUSTOM:
            for section in required_sections[report_type]:
                if section not in v:
                    raise ValueError(f"Missing required section for {report_type}: {section}")
        
        return v
    
    @validator("parameters")
    def validate_parameters(cls, v):
        """Validate template parameters."""
        required_fields = ["title", "date_range", "filters"]
        for field in required_fields:
            if field not in v:
                raise ValueError(f"Missing required parameter: {field}")
        return v

class Report(BaseModelWithMetadata):
    """Report model."""
    template_id: UUID
    parameters: Dict[str, Any]
    status: ReportStatus = ReportStatus.PENDING
    formats: List[ReportFormat]
    generated_files: Dict[str, str] = Field(default_factory=dict)
    generation_time: Optional[float] = None
    error_message: Optional[str] = None
    expiration_date: Optional[datetime] = None
    downloaded_count: int = 0
    last_downloaded: Optional[datetime] = None

class ReportSchedule(BaseModelWithMetadata):
    """Report schedule model."""
    template_id: UUID
    frequency: ReportScheduleFrequency
    parameters: Dict[str, Any]
    formats: List[ReportFormat]
    time: time
    day_of_week: Optional[int] = None  # 0-6 for weekly
    day_of_month: Optional[int] = None  # 1-31 for monthly
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    recipients: List[str] = Field(default_factory=list)
    active: bool = True
    
    @validator("day_of_week")
    def validate_day_of_week(cls, v, values):
        """Validate day of week."""
        if values.get("frequency") == ReportScheduleFrequency.WEEKLY:
            if v is None or not 0 <= v <= 6:
                raise ValueError("Day of week must be between 0 and 6 for weekly schedule")
        return v
    
    @validator("day_of_month")
    def validate_day_of_month(cls, v, values):
        """Validate day of month."""
        if values.get("frequency") == ReportScheduleFrequency.MONTHLY:
            if v is None or not 1 <= v <= 31:
                raise ValueError("Day of month must be between 1 and 31 for monthly schedule")
        return v

class ReportDelivery(BaseModel):
    """Report delivery model."""
    report_id: UUID
    recipient: str
    delivery_method: str
    status: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    retry_count: int = 0
    error_message: Optional[str] = None

class ReportMetrics(BaseModel):
    """Report metrics model."""
    template_id: UUID
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    reports_generated: int
    average_generation_time: float
    error_rate: float
    most_used_formats: Dict[str, int]
    popular_parameters: Dict[str, int]
    delivery_success_rate: float 