from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from uuid import UUID

from pydantic import Field, validator

from .base import BaseModelWithMetadata
from .alert import Alert
from .incident import Incident

class CorrelationRuleType(str, Enum):
    """Correlation rule type enumeration."""
    SEQUENCE = "sequence"
    THRESHOLD = "threshold"
    PATTERN = "pattern"
    ANOMALY = "anomaly"

class CorrelationRuleStatus(str, Enum):
    """Correlation rule status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    TESTING = "testing"
    DISABLED = "disabled"

class CorrelationSeverity(str, Enum):
    """Correlation severity enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class CorrelationRule(BaseModelWithMetadata):
    """Correlation rule model."""
    name: str
    rule_type: CorrelationRuleType
    status: CorrelationRuleStatus = CorrelationRuleStatus.TESTING
    severity: CorrelationSeverity
    conditions: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    timeframe_minutes: int = 60
    threshold: Optional[int] = None
    pattern: Optional[str] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    false_positives: int = 0
    true_positives: int = 0
    last_triggered: Optional[datetime] = None
    
    @validator("conditions")
    def validate_conditions(cls, v, values):
        """Validate rule conditions based on type."""
        rule_type = values.get("rule_type")
        if not rule_type:
            return v
            
        if not v:
            raise ValueError("Rule must have at least one condition")
            
        required_fields = {
            CorrelationRuleType.SEQUENCE: ["event_type", "order"],
            CorrelationRuleType.THRESHOLD: ["event_type", "count"],
            CorrelationRuleType.PATTERN: ["field", "pattern"],
            CorrelationRuleType.ANOMALY: ["metric", "threshold"]
        }
        
        if rule_type in required_fields:
            for condition in v:
                for field in required_fields[rule_type]:
                    if field not in condition:
                        raise ValueError(f"Missing required field in condition for {rule_type}: {field}")
        
        return v
    
    @validator("actions")
    def validate_actions(cls, v):
        """Validate rule actions."""
        if not v:
            raise ValueError("Rule must have at least one action")
            
        valid_actions = ["create_alert", "create_incident", "block_ip", "notify"]
        for action in v:
            if "type" not in action:
                raise ValueError("Action must have a type")
            if action["type"] not in valid_actions:
                raise ValueError(f"Invalid action type: {action['type']}")
        
        return v

class CorrelationEvent(BaseModelWithMetadata):
    """Correlation event model."""
    rule_id: UUID
    severity: CorrelationSeverity
    source_events: List[Dict[str, Any]]
    matched_condition: Dict[str, Any]
    triggered_actions: List[Dict[str, Any]]
    alert_ids: List[UUID] = Field(default_factory=list)
    incident_ids: List[UUID] = Field(default_factory=list)
    false_positive: bool = False
    analyst_feedback: Optional[str] = None

class EventChain(BaseModel):
    """Event chain model for correlation analysis."""
    chain_id: UUID = Field(default_factory=uuid4)
    root_event_id: UUID
    events: List[Dict[str, Any]]
    alerts: List[Alert]
    incidents: List[Incident]
    first_seen: datetime
    last_seen: datetime
    severity: CorrelationSeverity
    confidence: float
    analysis: Optional[Dict[str, Any]] = None
    recommendations: List[str] = Field(default_factory=list)

class CampaignPattern(BaseModel):
    """Campaign pattern model for attack campaign detection."""
    pattern_id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    indicators: List[Dict[str, Any]]
    ttps: List[str] = Field(default_factory=list)
    confidence: float
    first_seen: datetime
    last_seen: datetime
    affected_assets: List[str] = Field(default_factory=list)
    related_campaigns: List[UUID] = Field(default_factory=list)

class CorrelationMetrics(BaseModel):
    """Correlation metrics model."""
    rule_id: UUID
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    events_processed: int
    matches_found: int
    actions_triggered: int
    average_processing_time: float
    false_positive_rate: float
    true_positive_rate: float
    precision: float
    recall: float 