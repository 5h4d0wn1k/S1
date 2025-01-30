from typing import Dict, List
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from ...data.models.scan import ScanResult, ScanTarget, ScanStatus
from ...engines.offensive.engine import offensive_engine
from ...utils.logging import LoggerMixin

router = APIRouter()
logger = LoggerMixin()

@router.post("/", response_model=ScanResult)
async def start_scan(target: ScanTarget) -> ScanResult:
    """Start a new security scan."""
    try:
        scan = await offensive_engine.schedule_scan(target)
        return scan
        
    except Exception as e:
        logger.log_error("Failed to start scan", error=e, target=target.model_dump())
        raise HTTPException(
            status_code=500,
            detail="Failed to start scan"
        )

@router.get("/", response_model=List[ScanResult])
async def list_scans(
    status: ScanStatus = None,
    limit: int = Query(default=50, ge=1, le=100)
) -> List[ScanResult]:
    """List security scans with optional filtering."""
    try:
        scans = list(offensive_engine.active_scans.values())
        
        # Apply filters
        if status:
            scans = [scan for scan in scans if scan.status == status]
        
        # Sort by start time and limit
        scans.sort(key=lambda x: x.start_time, reverse=True)
        return scans[:limit]
        
    except Exception as e:
        logger.log_error("Failed to list scans", error=e)
        raise HTTPException(
            status_code=500,
            detail="Failed to list scans"
        )

@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: UUID) -> ScanResult:
    """Get details of a specific scan."""
    try:
        scan = await offensive_engine.get_scan_status(scan_id)
        return scan
        
    except Exception as e:
        logger.log_error("Failed to get scan", error=e, scan_id=str(scan_id))
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found"
        )

@router.delete("/{scan_id}")
async def cancel_scan(scan_id: UUID) -> Dict:
    """Cancel a running scan."""
    try:
        scan = await offensive_engine.get_scan_status(scan_id)
        
        if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
            raise HTTPException(
                status_code=400,
                detail="Can only cancel pending or running scans"
            )
        
        scan.status = ScanStatus.CANCELLED
        scan.end_time = datetime.now()
        
        return {"message": f"Scan {scan_id} cancelled"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.log_error("Failed to cancel scan", error=e, scan_id=str(scan_id))
        raise HTTPException(
            status_code=500,
            detail="Failed to cancel scan"
        )

@router.post("/batch")
async def batch_scan(targets: List[ScanTarget]) -> Dict:
    """Start multiple scans in batch."""
    try:
        results = []
        failed = []
        
        for target in targets:
            try:
                scan = await offensive_engine.schedule_scan(target)
                results.append(scan.id)
            except Exception as e:
                logger.log_error(
                    "Failed to schedule scan in batch",
                    error=e,
                    target=target.model_dump()
                )
                failed.append(target.name)
        
        return {
            "scheduled": len(results),
            "failed": len(failed),
            "scan_ids": results,
            "failed_targets": failed
        }
        
    except Exception as e:
        logger.log_error("Failed to process batch scan", error=e)
        raise HTTPException(
            status_code=500,
            detail="Failed to process batch scan"
        )

@router.get("/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(
    scan_id: UUID,
    severity: str = None,
    limit: int = Query(default=50, ge=1, le=100)
) -> Dict:
    """Get vulnerabilities found in a scan."""
    try:
        scan = await offensive_engine.get_scan_status(scan_id)
        
        vulnerabilities = scan.vulnerabilities
        if severity:
            vulnerabilities = [v for v in vulnerabilities if v.severity == severity]
        
        # Update summary statistics
        scan.update_summary()
        
        return {
            "scan_id": scan_id,
            "total": len(vulnerabilities),
            "summary": scan.findings_summary,
            "vulnerabilities": vulnerabilities[:limit]
        }
        
    except Exception as e:
        logger.log_error(
            "Failed to get scan vulnerabilities",
            error=e,
            scan_id=str(scan_id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to get scan vulnerabilities"
        ) 