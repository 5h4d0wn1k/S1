from typing import Dict, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import User, requires_permissions
from ...engines.offensive.engine import (
    ScanTarget,
    ScanResult,
    Vulnerability,
    offensive_engine
)
from ...utils.logging import LoggerMixin

router = APIRouter()
logger = LoggerMixin()

@router.post("/scans", response_model=ScanResult)
async def start_scan(
    target: ScanTarget,
    current_user: User = Depends(requires_permissions("offensive:scan"))
) -> ScanResult:
    """Start a new security scan."""
    try:
        logger.log_info(
            "Starting new scan",
            target=target.host,
            user=current_user.username
        )
        
        scan = await offensive_engine.schedule_scan(target)
        return scan
    except Exception as e:
        logger.log_error(
            "Failed to start scan",
            error=e,
            target=target.model_dump(),
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start security scan"
        )

@router.get("/scans/{scan_id}", response_model=ScanResult)
async def get_scan_status(
    scan_id: UUID,
    current_user: User = Depends(requires_permissions("offensive:read"))
) -> ScanResult:
    """Get the status of a specific scan."""
    try:
        logger.log_info(
            "Retrieving scan status",
            scan_id=str(scan_id),
            user=current_user.username
        )
        
        scan = await offensive_engine.get_scan_status(scan_id)
        return scan
    except Exception as e:
        logger.log_error(
            "Failed to get scan status",
            error=e,
            scan_id=str(scan_id),
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

@router.get("/scans/{scan_id}/vulnerabilities", response_model=List[Vulnerability])
async def get_scan_vulnerabilities(
    scan_id: UUID,
    current_user: User = Depends(requires_permissions("offensive:read"))
) -> List[Vulnerability]:
    """Get vulnerabilities found in a specific scan."""
    try:
        logger.log_info(
            "Retrieving scan vulnerabilities",
            scan_id=str(scan_id),
            user=current_user.username
        )
        
        scan = await offensive_engine.get_scan_status(scan_id)
        return scan.vulnerabilities
    except Exception as e:
        logger.log_error(
            "Failed to get scan vulnerabilities",
            error=e,
            scan_id=str(scan_id),
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

@router.post("/scans/{scan_id}/stop")
async def stop_scan(
    scan_id: UUID,
    current_user: User = Depends(requires_permissions("offensive:manage"))
) -> Dict[str, str]:
    """Stop a running scan."""
    try:
        logger.log_info(
            "Stopping scan",
            scan_id=str(scan_id),
            user=current_user.username
        )
        
        scan = await offensive_engine.get_scan_status(scan_id)
        if scan.status != "running":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scan is not running"
            )
        
        # Here you would implement scan stopping logic
        scan.status = "stopped"
        scan.end_time = datetime.utcnow()
        
        return {"message": "Scan stopped successfully"}
    except Exception as e:
        logger.log_error(
            "Failed to stop scan",
            error=e,
            scan_id=str(scan_id),
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to stop scan"
        )

@router.post("/scans/{scan_id}/report")
async def generate_scan_report(
    scan_id: UUID,
    current_user: User = Depends(requires_permissions("offensive:read"))
) -> Dict[str, Any]:
    """Generate a detailed report for a completed scan."""
    try:
        logger.log_info(
            "Generating scan report",
            scan_id=str(scan_id),
            user=current_user.username
        )
        
        scan = await offensive_engine.get_scan_status(scan_id)
        if scan.status != "completed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scan is not completed"
            )
        
        # Here you would implement report generation logic
        report = {
            "scan_id": str(scan_id),
            "target": scan.target.model_dump(),
            "summary": {
                "total_vulnerabilities": len(scan.vulnerabilities),
                "critical": len([v for v in scan.vulnerabilities if v.level == "critical"]),
                "high": len([v for v in scan.vulnerabilities if v.level == "high"]),
                "medium": len([v for v in scan.vulnerabilities if v.level == "medium"]),
                "low": len([v for v in scan.vulnerabilities if v.level == "low"])
            },
            "vulnerabilities": [v.model_dump() for v in scan.vulnerabilities],
            "recommendations": [
                {
                    "title": v.title,
                    "remediation": v.remediation
                }
                for v in scan.vulnerabilities
                if v.remediation
            ]
        }
        
        return report
    except Exception as e:
        logger.log_error(
            "Failed to generate scan report",
            error=e,
            scan_id=str(scan_id),
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate scan report"
        ) 