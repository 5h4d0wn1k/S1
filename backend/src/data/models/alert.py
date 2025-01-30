from datetime import datetime
from enum import Enum
from typing import Dict, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, IPvAnyAddress

class AlertSeverity(str, Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AlertCategory(str, Enum):
    """Alert categories."""
    NETWORK = "network"
    ENDPOINT = "endpoint"
    APPLICATION = "application"
    CLOUD = "cloud"
    IDENTITY = "identity"
    MALWARE = "malware"
    OTHER = "other"

class Alert(BaseModel):
    """Security alert model."""
    
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.now)
    source: str = Field(..., description="Alert source (e.g., 'suricata', 'wazuh')")
    severity: AlertSeverity
    category: AlertCategory
    description: str = Field(..., min_length=1, max_length=1000)
    
    # Network details
    source_ip: Optional[IPvAnyAddress] = None
    destination_ip: Optional[IPvAnyAddress] = None
    source_port: Optional[int] = Field(None, ge=0, le=65535)
    destination_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = None
    
    # Additional context
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    
    # Raw alert data
    raw_data: Dict = Field(default_factory=dict)
    
    class Config:
        """Pydantic model configuration."""
        json_schema_extra = {
            "example": {
                "source": "suricata",
                "severity": "high",
                "category": "network",
                "description": "Possible SQL injection attempt detected",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.5",
                "source_port": 12345,
                "destination_port": 80,
                "protocol": "TCP",
                "mitre_tactics": ["initial-access", "credential-access"],
                "mitre_techniques": ["T1190", "T1552"],
                "indicators": ["SELECT FROM users--", "UNION ALL SELECT"]
            }
        } 