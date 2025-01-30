from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

class AnomalyScore(BaseModel):
    """Model representing an anomaly detection score for an alert."""
    
    alert_id: UUID
    score: float = Field(..., ge=0, le=1, description="Anomaly score between 0 and 1")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    features: Dict[str, float] = Field(
        ..., 
        description="Feature importance scores that contributed to the anomaly detection"
    )
    threshold: float = Field(..., ge=0, le=1, description="Threshold used for anomaly detection")
    is_anomaly: bool = Field(..., description="Whether the score exceeds the threshold")
    
    class Config:
        """Pydantic model configuration."""
        json_schema_extra = {
            "example": {
                "alert_id": "123e4567-e89b-12d3-a456-426614174000",
                "score": 0.87,
                "timestamp": "2024-01-20T10:00:00Z",
                "features": {
                    "request_frequency": 0.6,
                    "bytes_transferred": 0.8,
                    "time_of_day": 0.3
                },
                "threshold": 0.75,
                "is_anomaly": True
            }
        }

class ThreatPrediction(BaseModel):
    """Model representing a threat classification prediction for an alert."""
    
    alert_id: UUID
    threat_type: str = Field(..., description="Predicted type of threat")
    confidence: float = Field(..., ge=0, le=1, description="Confidence score of prediction")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    evidence: List[str] = Field(..., description="Evidence supporting the prediction")
    severity: str = Field(..., description="Predicted severity level")
    tactics: List[str] = Field(..., description="MITRE ATT&CK tactics identified")
    techniques: List[str] = Field(..., description="MITRE ATT&CK techniques identified")
    
    class Config:
        """Pydantic model configuration."""
        json_schema_extra = {
            "example": {
                "alert_id": "123e4567-e89b-12d3-a456-426614174000",
                "threat_type": "Malware",
                "confidence": 0.95,
                "timestamp": "2024-01-20T10:00:00Z",
                "evidence": [
                    "Suspicious process creation",
                    "Network connection to known C2",
                    "File system modifications"
                ],
                "severity": "HIGH",
                "tactics": ["Initial Access", "Execution", "Command and Control"],
                "techniques": ["T1190", "T1059", "T1071"]
            }
        }

class AlertAnalysis(BaseModel):
    """Model representing a detailed analysis of an alert."""
    
    alert_id: UUID
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    analysis: str = Field(..., description="Detailed analysis text")
    recommendations: List[str] = Field(..., description="List of recommended actions")
    related_alerts: Optional[List[UUID]] = Field(
        default=None, 
        description="IDs of related alerts"
    )
    risk_score: Optional[float] = Field(
        default=None,
        ge=0,
        le=100,
        description="Risk score from 0-100"
    )
    context: Optional[Dict] = Field(
        default=None,
        description="Additional context information"
    )
    
    class Config:
        """Pydantic model configuration."""
        json_schema_extra = {
            "example": {
                "alert_id": "123e4567-e89b-12d3-a456-426614174000",
                "timestamp": "2024-01-20T10:00:00Z",
                "analysis": "Alert indicates a potential SQL injection attempt...",
                "recommendations": [
                    "Block source IP",
                    "Update WAF rules",
                    "Review application logs"
                ],
                "related_alerts": [
                    "223e4567-e89b-12d3-a456-426614174001",
                    "323e4567-e89b-12d3-a456-426614174002"
                ],
                "risk_score": 85,
                "context": {
                    "previous_incidents": 3,
                    "asset_criticality": "HIGH",
                    "affected_systems": ["web-server-01", "database-01"]
                }
            }
        }

class ThreatIntelligence(BaseModel):
    """Threat intelligence data for an indicator."""
    
    indicator: str = Field(..., description="Indicator of compromise (IoC)")
    type: str = Field(..., description="Type of indicator (IP, domain, hash, etc.)")
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: int = Field(..., ge=1, le=10)
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    
    class Config:
        """Pydantic model configuration."""
        json_schema_extra = {
            "example": {
                "indicator": "185.159.83.24",
                "type": "ip",
                "confidence": 0.95,
                "severity": 8,
                "first_seen": "2024-01-15T00:00:00Z",
                "last_seen": "2024-01-30T12:00:00Z",
                "tags": ["ransomware", "c2", "apt29"],
                "references": [
                    "https://example.com/threat-report-123",
                    "https://twitter.com/threatintel/status/123456789"
                ]
            }
        } 