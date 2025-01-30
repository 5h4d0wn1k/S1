from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from uuid import UUID

from pydantic import Field, validator

from .base import BaseModelWithMetadata

class ComplianceFrameworkType(str, Enum):
    """Compliance framework type enumeration."""
    ISO27001 = "iso27001"
    NIST = "nist"
    PCI = "pci"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    SOC2 = "soc2"
    CUSTOM = "custom"

class ComplianceStatus(str, Enum):
    """Compliance status enumeration."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    PENDING = "pending"

class ComplianceRiskLevel(str, Enum):
    """Compliance risk level enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ComplianceControlType(str, Enum):
    """Compliance control type enumeration."""
    TECHNICAL = "technical"
    ADMINISTRATIVE = "administrative"
    PHYSICAL = "physical"
    PROCEDURAL = "procedural"

class ComplianceAssessmentType(str, Enum):
    """Compliance assessment type enumeration."""
    AUTOMATED = "automated"
    MANUAL = "manual"
    HYBRID = "hybrid"

class ComplianceFramework(BaseModelWithMetadata):
    """Compliance framework model."""
    name: str
    type: ComplianceFrameworkType
    version: str
    description: str
    controls: List[Dict[str, Any]]
    requirements: Dict[str, Any]
    scope: Dict[str, Any]
    owner: str
    review_frequency: int  # days
    last_review: Optional[datetime] = None
    next_review: Optional[datetime] = None
    
    @validator("controls")
    def validate_controls(cls, v):
        """Validate framework controls."""
        if not v:
            raise ValueError("Framework must have at least one control")
            
        required_fields = ["id", "name", "description", "type", "requirements"]
        for control in v:
            for field in required_fields:
                if field not in control:
                    raise ValueError(f"Missing required field in control: {field}")
        
        return v

class ComplianceControl(BaseModelWithMetadata):
    """Compliance control model."""
    framework_id: UUID
    name: str
    description: str
    control_type: ComplianceControlType
    requirements: List[str]
    assessment_type: ComplianceAssessmentType
    assessment_frequency: int  # days
    evidence_required: List[str]
    automated_tests: Optional[List[Dict[str, Any]]] = None
    dependencies: List[str] = Field(default_factory=list)
    implementation_status: ComplianceStatus = ComplianceStatus.PENDING
    last_assessment: Optional[datetime] = None
    next_assessment: Optional[datetime] = None
    risk_level: ComplianceRiskLevel
    owner: str
    reviewers: List[str] = Field(default_factory=list)
    
    @validator("automated_tests")
    def validate_automated_tests(cls, v, values):
        """Validate automated tests configuration."""
        if values.get("assessment_type") in [ComplianceAssessmentType.AUTOMATED, ComplianceAssessmentType.HYBRID]:
            if not v:
                raise ValueError("Automated tests required for automated/hybrid assessment type")
            
            required_fields = ["name", "type", "parameters", "expected_result"]
            for test in v:
                for field in required_fields:
                    if field not in test:
                        raise ValueError(f"Missing required field in automated test: {field}")
        
        return v

class ComplianceAssessment(BaseModelWithMetadata):
    """Compliance assessment model."""
    framework_id: UUID
    assessor: str
    assessment_type: ComplianceAssessmentType
    start_date: datetime
    end_date: Optional[datetime] = None
    status: ComplianceStatus = ComplianceStatus.PENDING
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    score: Optional[float] = None
    recommendations: List[str] = Field(default_factory=list)
    remediation_plan: Optional[Dict[str, Any]] = None
    attachments: List[Dict[str, str]] = Field(default_factory=list)
    reviewer: Optional[str] = None
    review_notes: Optional[str] = None
    review_date: Optional[datetime] = None

class ComplianceEvidence(BaseModelWithMetadata):
    """Compliance evidence model."""
    control_id: UUID
    assessment_id: UUID
    type: str
    content: Any
    source: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    verified: bool = False
    verified_by: Optional[str] = None
    verification_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None

class ComplianceException(BaseModelWithMetadata):
    """Compliance exception model."""
    control_id: UUID
    reason: str
    risk_assessment: Dict[str, Any]
    mitigating_controls: List[str]
    approved_by: str
    approval_date: datetime
    expiration_date: datetime
    review_frequency: int  # days
    last_review: Optional[datetime] = None
    next_review: Optional[datetime] = None
    status: str = "active"

class ComplianceMetrics(BaseModel):
    """Compliance metrics model."""
    framework_id: UUID
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    not_applicable_controls: int
    pending_controls: int
    overall_compliance_rate: float
    risk_levels: Dict[str, int]
    assessment_coverage: float
    average_assessment_time: float
    overdue_assessments: int
    upcoming_assessments: int 