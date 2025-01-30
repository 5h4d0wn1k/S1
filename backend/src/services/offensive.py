from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models.scan import ScanResult, ScanTarget, ScanStatus, Vulnerability
from ..engines.offensive.engine import offensive_engine
from ..utils.logging import LoggerMixin
from ..core.exceptions import ResourceNotFoundError

class OffensiveService(LoggerMixin):
    """Service for handling offensive security operations."""
    
    async def start_scan(
        self,
        target: ScanTarget,
        scan_type: str = "full"
    ) -> ScanResult:
        """Start a new security scan."""
        try:
            # Schedule scan
            scan = await offensive_engine.schedule_scan(target)
            
            self.log_info(
                "Scan started",
                scan_id=scan.id,
                target=target.name,
                scan_type=scan_type
            )
            
            return scan
            
        except Exception as e:
            self.log_error(
                "Failed to start scan",
                error=e,
                target=target.model_dump()
            )
            raise
    
    async def get_scan_status(
        self,
        scan_id: UUID
    ) -> ScanResult:
        """Get scan status."""
        try:
            scan = await offensive_engine.get_scan_status(scan_id)
            if not scan:
                raise ResourceNotFoundError("Scan not found")
            return scan
            
        except ResourceNotFoundError:
            raise
        except Exception as e:
            self.log_error(
                "Failed to get scan status",
                error=e,
                scan_id=scan_id
            )
            raise
    
    async def cancel_scan(
        self,
        scan_id: UUID
    ) -> bool:
        """Cancel running scan."""
        try:
            # Get scan
            scan = await self.get_scan_status(scan_id)
            
            # Validate scan can be cancelled
            if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
                raise ValueError("Can only cancel pending or running scans")
            
            # Update scan status
            scan.status = ScanStatus.CANCELLED
            scan.end_time = datetime.utcnow()
            
            self.log_info(
                "Scan cancelled",
                scan_id=scan_id,
                target=scan.target.name
            )
            
            return True
            
        except Exception as e:
            self.log_error(
                "Failed to cancel scan",
                error=e,
                scan_id=scan_id
            )
            raise
    
    async def batch_scan(
        self,
        targets: List[ScanTarget]
    ) -> Dict:
        """Start multiple scans in batch."""
        try:
            results = []
            failed = []
            
            for target in targets:
                try:
                    scan = await self.start_scan(target)
                    results.append(scan.id)
                except Exception as e:
                    failed.append(target.name)
                    self.log_error(
                        "Failed to schedule scan in batch",
                        error=e,
                        target=target.model_dump()
                    )
            
            return {
                "scheduled": len(results),
                "failed": len(failed),
                "scan_ids": results,
                "failed_targets": failed
            }
            
        except Exception as e:
            self.log_error("Failed to process batch scan", error=e)
            raise
    
    async def get_vulnerabilities(
        self,
        scan_id: UUID,
        severity: Optional[str] = None,
        limit: int = 50
    ) -> Dict:
        """Get vulnerabilities found in scan."""
        try:
            # Get scan
            scan = await self.get_scan_status(scan_id)
            
            # Filter vulnerabilities
            vulnerabilities = scan.vulnerabilities
            if severity:
                vulnerabilities = [v for v in vulnerabilities if v.severity == severity]
            
            # Update summary
            scan.update_summary()
            
            return {
                "scan_id": scan_id,
                "total": len(vulnerabilities),
                "summary": scan.findings_summary,
                "vulnerabilities": vulnerabilities[:limit]
            }
            
        except Exception as e:
            self.log_error(
                "Failed to get scan vulnerabilities",
                error=e,
                scan_id=scan_id
            )
            raise
    
    async def get_active_scans(
        self,
        limit: int = 50
    ) -> List[ScanResult]:
        """Get active scans."""
        try:
            scans = list(offensive_engine.active_scans.values())
            
            # Sort by start time
            scans.sort(key=lambda x: x.start_time, reverse=True)
            
            return scans[:limit]
            
        except Exception as e:
            self.log_error("Failed to get active scans", error=e)
            raise
    
    async def get_scan_metrics(self) -> Dict:
        """Get scan metrics."""
        try:
            active_scans = list(offensive_engine.active_scans.values())
            
            metrics = {
                "total_scans": len(active_scans),
                "running": len([s for s in active_scans if s.status == ScanStatus.RUNNING]),
                "pending": len([s for s in active_scans if s.status == ScanStatus.PENDING]),
                "completed": len([s for s in active_scans if s.status == ScanStatus.COMPLETED]),
                "failed": len([s for s in active_scans if s.status == ScanStatus.FAILED]),
                "cancelled": len([s for s in active_scans if s.status == ScanStatus.CANCELLED]),
                "vulnerabilities": {
                    "critical": sum(s.findings_summary.get("critical", 0) for s in active_scans),
                    "high": sum(s.findings_summary.get("high", 0) for s in active_scans),
                    "medium": sum(s.findings_summary.get("medium", 0) for s in active_scans),
                    "low": sum(s.findings_summary.get("low", 0) for s in active_scans),
                    "info": sum(s.findings_summary.get("info", 0) for s in active_scans)
                }
            }
            
            return metrics
            
        except Exception as e:
            self.log_error("Failed to get scan metrics", error=e)
            raise

# Create service instance
offensive_service = OffensiveService() 