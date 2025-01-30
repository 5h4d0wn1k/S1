import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from uuid import UUID, uuid4
import logging
from pathlib import Path
import json
import subprocess

from pydantic import BaseModel, Field
from fastapi import HTTPException
from pymetasploit3.msfrpc import MsfRpcClient
import yaml

from ...core.exceptions import OffensiveEngineError
from ...utils.logging import LoggerMixin
from ...core.settings import get_settings
from ...data.models.scan import ScanResult, ScanTarget, ScanStatus, Vulnerability

settings = get_settings()

class ScanTarget(BaseModel):
    """Target for security scanning."""
    host: str
    port_range: str = "1-65535"
    scan_type: str = "full"
    options: Dict[str, Any] = Field(default_factory=dict)

class VulnerabilityLevel(str):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Vulnerability(BaseModel):
    """Detected vulnerability."""
    id: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    level: VulnerabilityLevel
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

class OffensiveEngine(LoggerMixin):
    """Core offensive engine integrating Metasploit and Nuclei."""
    
    def __init__(self):
        """Initialize offensive engine components."""
        super().__init__()
        self.msf_client = None
        self.active_scans: Dict[UUID, ScanResult] = {}
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize connections to offensive tools."""
        try:
            # Initialize Metasploit RPC client
            self.msf_client = MsfRpcClient(
                settings.METASPLOIT_PASSWORD,
                server=settings.METASPLOIT_HOST,
                port=settings.METASPLOIT_PORT,
                ssl=True
            )
            
            # Verify Nuclei installation
            try:
                subprocess.run(
                    ["nuclei", "-version"],
                    capture_output=True,
                    check=True
                )
            except subprocess.CalledProcessError:
                self.log_error("Nuclei not found or not properly installed")
                raise RuntimeError("Nuclei not found")
            
            self.log_info("Offensive engine components initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize offensive components", error=e)
            raise
    
    async def schedule_scan(self, target: ScanTarget) -> ScanResult:
        """Schedule a new security scan."""
        try:
            scan_id = uuid4()
            
            # Create scan result object
            scan = ScanResult(
                id=scan_id,
                target=target,
                status=ScanStatus.PENDING,
                start_time=datetime.utcnow()
            )
            
            # Store scan
            self.active_scans[scan_id] = scan
            
            # Start scan in background
            asyncio.create_task(self._run_scan(scan_id))
            
            return scan
            
        except Exception as e:
            self.log_error("Failed to schedule scan", error=e, target=target.model_dump())
            raise HTTPException(
                status_code=500,
                detail="Failed to schedule scan"
            )
    
    async def get_scan_status(self, scan_id: UUID) -> ScanResult:
        """Get the status of a specific scan."""
        try:
            if scan_id not in self.active_scans:
                raise HTTPException(
                    status_code=404,
                    detail=f"Scan {scan_id} not found"
                )
            
            return self.active_scans[scan_id]
            
        except HTTPException:
            raise
        except Exception as e:
            self.log_error("Failed to get scan status", error=e, scan_id=str(scan_id))
            raise HTTPException(
                status_code=500,
                detail="Failed to get scan status"
            )
    
    async def _run_scan(self, scan_id: UUID):
        """Run the actual security scan."""
        scan = self.active_scans[scan_id]
        
        try:
            scan.status = ScanStatus.RUNNING
            
            # Run scans concurrently
            metasploit_task = self._run_metasploit_scan(scan)
            nuclei_task = self._run_nuclei_scan(scan)
            
            # Gather results
            metasploit_vulns, nuclei_vulns = await asyncio.gather(
                metasploit_task,
                nuclei_task
            )
            
            # Combine and deduplicate vulnerabilities
            all_vulns = self._deduplicate_vulnerabilities(
                metasploit_vulns + nuclei_vulns
            )
            
            # Update scan result
            scan.vulnerabilities = all_vulns
            scan.status = ScanStatus.COMPLETED
            scan.end_time = datetime.utcnow()
            scan.update_summary()
            
            self.log_info(
                "Scan completed successfully",
                scan_id=str(scan_id),
                vulnerabilities=len(all_vulns)
            )
            
        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.end_time = datetime.utcnow()
            scan.error_message = str(e)
            
            self.log_error(
                "Scan failed",
                error=e,
                scan_id=str(scan_id)
            )
    
    async def _run_metasploit_scan(self, scan: ScanResult) -> List[Vulnerability]:
        """Run Metasploit modules against the target."""
        try:
            vulnerabilities = []
            
            # Get target info
            target = scan.target
            
            # Select appropriate modules based on target type
            modules = self._select_metasploit_modules(target)
            
            for module in modules:
                try:
                    # Initialize module
                    exploit = self.msf_client.modules.use('exploit', module)
                    
                    # Set options
                    exploit['RHOSTS'] = target.host
                    if hasattr(target, 'port'):
                        exploit['RPORT'] = target.port
                    
                    # Run exploit
                    result = exploit.execute()
                    
                    # Check if vulnerable
                    if result.get('success'):
                        vulnerabilities.append(
                            Vulnerability(
                                title=f"Metasploit: {module}",
                                description=result.get('description', 'No description available'),
                                severity="HIGH",  # Adjust based on module info
                                tool="metasploit",
                                evidence=json.dumps(result),
                                remediation="Patch system and disable vulnerable service"
                            )
                        )
                
                except Exception as e:
                    self.log_error(
                        "Metasploit module execution failed",
                        error=e,
                        module=module,
                        target=target.model_dump()
                    )
                    continue
            
            return vulnerabilities
            
        except Exception as e:
            self.log_error("Metasploit scan failed", error=e)
            raise
    
    async def _run_nuclei_scan(self, scan: ScanResult) -> List[Vulnerability]:
        """Run Nuclei templates against the target."""
        try:
            vulnerabilities = []
            
            # Get target info
            target = scan.target
            
            # Prepare Nuclei command
            cmd = [
                "nuclei",
                "-u", target.host,
                "-json",
                "-severity", "critical,high,medium,low",
                "-silent"
            ]
            
            if target.type == "web":
                cmd.extend(["-tags", "cve,vulnscan,tech-detect"])
            
            # Run Nuclei
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Process results
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                    
                try:
                    result = json.loads(line)
                    
                    vulnerabilities.append(
                        Vulnerability(
                            title=result.get('info', {}).get('name', 'Unknown'),
                            description=result.get('info', {}).get('description', ''),
                            severity=result.get('info', {}).get('severity', 'MEDIUM').upper(),
                            tool="nuclei",
                            evidence=line.decode(),
                            remediation=result.get('info', {}).get('remediation', '')
                        )
                    )
                    
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    self.log_error("Failed to parse Nuclei result", error=e, line=line)
                    continue
            
            # Wait for process to complete
            await process.wait()
            
            return vulnerabilities
            
        except Exception as e:
            self.log_error("Nuclei scan failed", error=e)
            raise
    
    def _select_metasploit_modules(self, target: ScanTarget) -> List[str]:
        """Select appropriate Metasploit modules based on target type."""
        modules = []
        
        if target.type == "web":
            modules.extend([
                "multi/http/apache_mod_cgi_bash_env_exec",  # Shellshock
                "multi/http/struts2_content_type_ognl",     # Struts
                "multi/http/tomcat_mgr_upload",             # Tomcat
                "multi/http/jenkins_script_console"          # Jenkins
            ])
        elif target.type == "service":
            modules.extend([
                "multi/misc/java_rmi_server",
                "multi/misc/weblogic_deserialize",
                "multi/misc/redis_unauth"
            ])
        elif target.type == "database":
            modules.extend([
                "multi/mysql/mysql_udf_payload",
                "multi/postgres/postgres_copy_from_program"
            ])
        
        return modules
    
    def _deduplicate_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """Deduplicate vulnerabilities based on title and description."""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            key = f"{vuln.title}:{vuln.description}"
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns

# Create singleton instance
offensive_engine = OffensiveEngine() 