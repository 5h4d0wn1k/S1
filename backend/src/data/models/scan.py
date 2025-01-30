from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, HttpUrl, IPvAnyAddress

class ScanStatus(str, Enum):
    """Status of a security scan."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class VulnerabilitySeverity(str, Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Vulnerability(BaseModel):
    """Vulnerability found during a scan."""
    
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    severity: VulnerabilitySeverity
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cve_ids: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    references: List[HttpUrl] = Field(default_factory=list)
    
    # Technical details
    affected_component: Optional[str] = None
    affected_versions: List[str] = Field(default_factory=list)
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    
    # MITRE ATT&CK mapping
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    
    class Config:
        """Pydantic model configuration."""
        json_schema_extra = {
            "example": {
                "name": "SQL Injection in Login Form",
                "description": "SQL injection vulnerability in the authentication endpoint allows arbitrary queries",
                "severity": "critical",
                "cvss_score": 9.8,
                "cve_ids": ["CVE-2024-1234"],
                "cwe_ids": ["CWE-89"],
                "references": [
                    "https://example.com/advisory/2024-001"
                ],
                "affected_component": "auth_service",
                "affected_versions": ["1.0.0", "1.1.0"],
                "proof_of_concept": "curl -X POST http://target/login --data 'username=admin\\'--",
                "remediation": "Update to version 1.1.1 or implement proper input validation",
                "mitre_tactics": ["initial-access", "credential-access"],
                "mitre_techniques": ["T1190"]
            }
        }

class ScanTarget(BaseModel):
    """Target of a security scan."""
    
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    
    # Target identifiers
    hostname: Optional[str] = None
    ip_address: Optional[IPvAnyAddress] = None
    url: Optional[HttpUrl] = None
    
    # Target metadata
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    services: Dict[str, str] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    
    class Config:
        """Pydantic model configuration."""
        json_schema_extra = {
            "example": {
                "name": "Production Web Server",
                "description": "Main production web server hosting the e-commerce platform",
                "hostname": "web01.prod.example.com",
                "ip_address": "192.168.1.100",
                "url": "https://example.com",
                "os_type": "linux",
                "os_version": "Ubuntu 22.04 LTS",
                "open_ports": [22, 80, 443],
                "services": {
                    "22": "OpenSSH 8.9",
                    "80": "nginx 1.18.0",
                    "443": "nginx 1.18.0"
                },
                "tags": ["production", "critical", "pci-dss"]
            }
        }

class ScanResult(BaseModel):
    """Results of a security scan."""
    
    id: UUID = Field(default_factory=uuid4)
    target: ScanTarget
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    
    # Timing information
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    
    # Scan configuration
    scan_type: str = Field(..., description="Type of scan (e.g., 'nuclei', 'metasploit')")
    scan_modules: List[str] = Field(default_factory=list)
    scan_options: Dict = Field(default_factory=dict)
    
    # Results
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    findings_summary: Dict[str, int] = Field(
        default_factory=lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
    )
    
    # Raw scan output
    raw_output: Dict = Field(default_factory=dict)
    error_message: Optional[str] = None
    
    def update_summary(self) -> None:
        """Update the findings summary based on vulnerabilities."""
        summary = {severity: 0 for severity in VulnerabilitySeverity}
        for vuln in self.vulnerabilities:
            summary[vuln.severity] += 1
        self.findings_summary = summary
    
    class Config:
        """Pydantic model configuration."""
        json_schema_extra = {
            "example": {
                "target": {
                    "name": "Production Web Server",
                    "hostname": "web01.prod.example.com",
                    "ip_address": "192.168.1.100"
                },
                "status": "completed",
                "start_time": "2024-01-30T12:00:00Z",
                "end_time": "2024-01-30T12:15:00Z",
                "duration_seconds": 900,
                "scan_type": "nuclei",
                "scan_modules": ["http", "ssl", "cves"],
                "scan_options": {
                    "concurrent": 10,
                    "rate_limit": 100
                },
                "findings_summary": {
                    "critical": 1,
                    "high": 3,
                    "medium": 5,
                    "low": 2,
                    "info": 10
                }
            }
        } 