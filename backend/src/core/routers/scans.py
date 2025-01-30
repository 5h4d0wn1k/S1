from typing import Dict, List, Optional, Union, Any
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ...data.connectors.postgresql import pg_connector
from ...data.connectors.kafka import kafka_connector
from ...utils.logging import LoggerMixin
from ...utils.auth import get_current_user
from ...data.models.user import User
from ...engines.offensive import offensive_engine
from ...engines.defensive import defensive_engine

router = APIRouter(prefix="/scans", tags=["scans"])
logger = LoggerMixin().get_logger()

class ScanType(str, Enum):
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    PENETRATION = "penetration"
    CONFIGURATION = "configuration"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanCreate(BaseModel):
    """Scan creation model."""
    type: ScanType
    target_id: UUID
    target_type: str = Field(..., description="Asset type (e.g., server, network)")
    configuration: Dict[str, Any] = Field(default_factory=dict)
    schedule: Optional[str] = Field(None, description="Cron expression for scheduled scans")

class ScanUpdate(BaseModel):
    """Scan update model."""
    status: Optional[ScanStatus] = None
    findings: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None

class ScanResponse(BaseModel):
    """Scan response model."""
    id: UUID
    type: ScanType
    target_id: UUID
    target_type: str
    configuration: Dict[str, Any]
    status: ScanStatus
    findings: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None
    schedule: Optional[str] = None
    created_by: UUID
    created_at: datetime
    updated_at: datetime
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

async def execute_scan(scan_id: UUID, scan_type: ScanType, target_id: UUID, configuration: Dict[str, Any]):
    """Background task to execute a scan."""
    try:
        # Update scan status
        await pg_connector.update(
            table="scans",
            data={
                "status": ScanStatus.RUNNING,
                "start_time": datetime.utcnow()
            },
            where={"id": str(scan_id)}
        )
        
        # Execute scan based on type
        if scan_type in [ScanType.VULNERABILITY, ScanType.PENETRATION]:
            findings = await offensive_engine.run_scan(
                target_id=target_id,
                scan_type=scan_type,
                configuration=configuration
            )
        else:
            findings = await defensive_engine.run_scan(
                target_id=target_id,
                scan_type=scan_type,
                configuration=configuration
            )
        
        # Update scan results
        await pg_connector.update(
            table="scans",
            data={
                "status": ScanStatus.COMPLETED,
                "findings": findings,
                "end_time": datetime.utcnow()
            },
            where={"id": str(scan_id)}
        )
        
        # Send scan completion notification
        await kafka_connector.send_message(
            topic="scans.completed",
            message={
                "scan_id": str(scan_id),
                "target_id": str(target_id),
                "findings": findings
            }
        )
        
    except Exception as e:
        logger.error(
            "Scan execution failed",
            error=str(e),
            scan_id=str(scan_id)
        )
        
        # Update scan status to failed
        await pg_connector.update(
            table="scans",
            data={
                "status": ScanStatus.FAILED,
                "notes": f"Failed: {str(e)}",
                "end_time": datetime.utcnow()
            },
            where={"id": str(scan_id)}
        )

@router.post("", response_model=ScanResponse)
async def create_scan(
    scan: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
) -> ScanResponse:
    """Create and start a new scan."""
    try:
        # Check permissions
        if not current_user.role in ["admin", "security_analyst"]:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions to create scans"
            )
        
        # Validate target exists
        target = await pg_connector.get_by_id(
            table="assets",
            id_=str(scan.target_id)
        )
        
        if not target:
            raise HTTPException(
                status_code=404,
                detail=f"Target asset {scan.target_id} not found"
            )
        
        # Create scan record
        scan_id = await pg_connector.insert(
            table="scans",
            data={
                "type": scan.type,
                "target_id": str(scan.target_id),
                "target_type": scan.target_type,
                "configuration": scan.configuration,
                "status": ScanStatus.PENDING,
                "schedule": scan.schedule,
                "created_by": str(current_user.id)
            }
        )
        
        # Get created scan
        result = await pg_connector.get_by_id(
            table="scans",
            id_=scan_id
        )
        
        # Schedule scan execution
        background_tasks.add_task(
            execute_scan,
            scan_id=UUID(scan_id),
            scan_type=scan.type,
            target_id=scan.target_id,
            configuration=scan.configuration
        )
        
        logger.info(
            "Scan created successfully",
            scan_id=str(scan_id),
            created_by=str(current_user.id)
        )
        
        return ScanResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to create scan",
            error=str(e),
            created_by=str(current_user.id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to create scan"
        )

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user)
) -> ScanResponse:
    """Get scan details by ID."""
    try:
        # Get scan
        result = await pg_connector.get_by_id(
            table="scans",
            id_=str(scan_id)
        )
        
        if not result:
            raise HTTPException(
                status_code=404,
                detail=f"Scan {scan_id} not found"
            )
        
        logger.info(
            "Scan retrieved successfully",
            scan_id=str(scan_id),
            retrieved_by=str(current_user.id)
        )
        
        return ScanResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to get scan",
            error=str(e),
            scan_id=str(scan_id),
            retrieved_by=str(current_user.id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to get scan"
        )

@router.patch("/{scan_id}", response_model=ScanResponse)
async def update_scan(
    scan_id: UUID,
    scan: ScanUpdate,
    current_user: User = Depends(get_current_user)
) -> ScanResponse:
    """Update scan details."""
    try:
        # Check permissions
        if not current_user.role in ["admin", "security_analyst"]:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions to update scans"
            )
        
        # Get existing scan
        existing = await pg_connector.get_by_id(
            table="scans",
            id_=str(scan_id)
        )
        
        if not existing:
            raise HTTPException(
                status_code=404,
                detail=f"Scan {scan_id} not found"
            )
        
        # Prepare update data
        update_data = {
            k: v for k, v in scan.model_dump().items()
            if v is not None
        }
        update_data["updated_at"] = datetime.utcnow()
        
        # Update scan
        rows_updated = await pg_connector.update(
            table="scans",
            data=update_data,
            where={"id": str(scan_id)}
        )
        
        if not rows_updated:
            raise HTTPException(
                status_code=500,
                detail="Failed to update scan"
            )
        
        # Get updated scan
        result = await pg_connector.get_by_id(
            table="scans",
            id_=str(scan_id)
        )
        
        logger.info(
            "Scan updated successfully",
            scan_id=str(scan_id),
            updated_by=str(current_user.id),
            updates=update_data
        )
        
        return ScanResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to update scan",
            error=str(e),
            scan_id=str(scan_id),
            updated_by=str(current_user.id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to update scan"
        )

@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    """Delete a scan."""
    try:
        # Check permissions
        if not current_user.role == "admin":
            raise HTTPException(
                status_code=403,
                detail="Only administrators can delete scans"
            )
        
        # Delete scan
        rows_deleted = await pg_connector.delete(
            table="scans",
            where={"id": str(scan_id)}
        )
        
        if not rows_deleted:
            raise HTTPException(
                status_code=404,
                detail=f"Scan {scan_id} not found"
            )
        
        logger.info(
            "Scan deleted successfully",
            scan_id=str(scan_id),
            deleted_by=str(current_user.id)
        )
        
        return JSONResponse(
            content={"message": "Scan deleted successfully"},
            status_code=200
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to delete scan",
            error=str(e),
            scan_id=str(scan_id),
            deleted_by=str(current_user.id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to delete scan"
        )

@router.get("", response_model=List[ScanResponse])
async def list_scans(
    target_id: Optional[UUID] = None,
    type: Optional[ScanType] = None,
    status: Optional[ScanStatus] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    current_user: User = Depends(get_current_user)
) -> List[ScanResponse]:
    """List scans with optional filtering."""
    try:
        # Build where clause
        where = {}
        if target_id:
            where["target_id"] = str(target_id)
        if type:
            where["type"] = type
        if status:
            where["status"] = status
        
        # Build query
        query = "SELECT * FROM scans"
        params = {}
        
        if where:
            conditions = []
            for k, v in where.items():
                conditions.append(f"{k} = :{k}")
                params[k] = v
            query += f" WHERE {' AND '.join(conditions)}"
        
        if start_time and end_time:
            time_condition = "created_at BETWEEN :start_time AND :end_time"
            query += f" AND {time_condition}" if where else f" WHERE {time_condition}"
            params.update({
                "start_time": start_time,
                "end_time": end_time
            })
        
        # Execute query
        results = await pg_connector.execute_query(query, params)
        
        logger.info(
            "Scans listed successfully",
            user_id=str(current_user.id),
            filters=where,
            count=len(results)
        )
        
        return [ScanResponse(**result) for result in results]
        
    except Exception as e:
        logger.error(
            "Failed to list scans",
            error=str(e),
            user_id=str(current_user.id),
            filters=locals()
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to list scans"
        )

@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    """Cancel a running scan."""
    try:
        # Check permissions
        if not current_user.role in ["admin", "security_analyst"]:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions to cancel scans"
            )
        
        # Get scan
        scan = await pg_connector.get_by_id(
            table="scans",
            id_=str(scan_id)
        )
        
        if not scan:
            raise HTTPException(
                status_code=404,
                detail=f"Scan {scan_id} not found"
            )
        
        if scan["status"] != ScanStatus.RUNNING:
            raise HTTPException(
                status_code=400,
                detail="Can only cancel running scans"
            )
        
        # Cancel scan based on type
        if scan["type"] in [ScanType.VULNERABILITY, ScanType.PENETRATION]:
            await offensive_engine.cancel_scan(scan_id)
        else:
            await defensive_engine.cancel_scan(scan_id)
        
        # Update scan status
        await pg_connector.update(
            table="scans",
            data={
                "status": ScanStatus.CANCELLED,
                "end_time": datetime.utcnow(),
                "notes": "Cancelled by user"
            },
            where={"id": str(scan_id)}
        )
        
        logger.info(
            "Scan cancelled successfully",
            scan_id=str(scan_id),
            cancelled_by=str(current_user.id)
        )
        
        return JSONResponse(
            content={"message": "Scan cancelled successfully"},
            status_code=200
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to cancel scan",
            error=str(e),
            scan_id=str(scan_id),
            cancelled_by=str(current_user.id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to cancel scan"
        ) 