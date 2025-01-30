from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import User, auth_manager, requires_permissions, get_current_active_user, get_current_superuser
from ..exceptions import ResourceNotFoundError
from ...utils.logging import LoggerMixin
from ...data.models.alert import Alert, AlertCategory, AlertSeverity, AlertStatus
from ...engines.defensive.engine import defensive_engine
from ...engines.ai.engine import ai_engine
from ...data.db import get_db
from ...data.repositories.alert import alert_repository

router = APIRouter()
logger = LoggerMixin()

# Models
class AlertSeverity(str):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertStatus(str):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class AlertBase(BaseModel):
    title: str
    description: str
    severity: AlertSeverity
    source: str
    source_type: str
    tags: List[str] = []
    raw_data: Dict[str, Any] = Field(default_factory=dict)

class AlertCreate(AlertBase):
    source_id: Optional[str] = None
    host: Optional[str] = None
    ip_address: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []

class Alert(AlertBase):
    id: UUID = Field(default_factory=uuid4)
    status: AlertStatus = AlertStatus.NEW
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    assigned_to: Optional[str] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None

class AlertUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[AlertSeverity] = None
    status: Optional[AlertStatus] = None
    tags: Optional[List[str]] = None
    false_positive_reason: Optional[str] = None
    resolution_notes: Optional[str] = None

class AlertResponse(BaseModel):
    uuid: UUID
    title: str
    description: str
    severity: AlertSeverity
    status: AlertStatus
    source: str
    source_id: Optional[str]
    host: Optional[str]
    ip_address: Optional[str]
    user: Optional[str]
    process: Optional[str]
    tags: List[str]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    enrichment: dict
    threat_intel: dict
    ai_analysis: Optional[dict]
    false_positive_reason: Optional[str]
    resolution_notes: Optional[str]
    detected_at: datetime
    resolved_at: Optional[datetime]
    assigned_to: Optional[str]
    incident_id: Optional[int]
    created_at: datetime
    updated_at: datetime

# Mock database (replace with real database operations)
alerts_db: Dict[UUID, Alert] = {}

@router.post("", response_model=AlertResponse)
async def create_alert(
    alert_in: AlertCreate,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Alert:
    """Create new alert."""
    try:
        # Check if alert already exists
        if alert_in.source_id:
            existing_alert = await alert_repository.get_by_source_id(
                session,
                alert_in.source,
                alert_in.source_id
            )
            if existing_alert:
                return existing_alert
        
        # Create alert
        alert = await alert_repository.create(
            session,
            {
                **alert_in.dict(),
                "status": AlertStatus.NEW,
                "detected_at": datetime.utcnow(),
                "enrichment": {},
                "threat_intel": {}
            }
        )
        
        await session.commit()
        
        # Log alert creation
        logger.log_info(
            "Alert created",
            alert_id=alert.uuid,
            title=alert.title,
            severity=alert.severity,
            source=alert.source
        )
        
        return alert
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to create alert", error=e)
        raise

@router.get("/", response_model=List[AlertResponse])
async def get_alerts(
    severity: Optional[AlertSeverity] = None,
    status: Optional[AlertStatus] = None,
    source: Optional[str] = None,
    host: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> List[Alert]:
    """Get alerts with filters."""
    try:
        if severity:
            return await alert_repository.get_alerts_by_severity(
                session,
                severity,
                skip=skip,
                limit=limit
            )
        elif status:
            return await alert_repository.get_alerts_by_status(
                session,
                status,
                skip=skip,
                limit=limit
            )
        elif source:
            return await alert_repository.get_alerts_by_source(
                session,
                source,
                skip=skip,
                limit=limit
            )
        elif host:
            return await alert_repository.get_alerts_by_host(
                session,
                host,
                skip=skip,
                limit=limit
            )
        elif start_time and end_time:
            return await alert_repository.get_alerts_by_timerange(
                session,
                start_time,
                end_time,
                skip=skip,
                limit=limit
            )
        else:
            return await alert_repository.get_all(
                session,
                skip=skip,
                limit=limit
            )
    except Exception as e:
        logger.log_error("Failed to get alerts", error=e)
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve alerts"
        )

@router.get("/active", response_model=List[AlertResponse])
async def get_active_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> List[Alert]:
    """Get active alerts."""
    try:
        return await alert_repository.get_active_alerts(
            session,
            skip=skip,
            limit=limit
        )
    except Exception as e:
        logger.log_error("Failed to get active alerts", error=e)
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve active alerts"
        )

@router.get("/stats")
async def get_alert_stats(
    days: int = Query(7, ge=1, le=90),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> dict:
    """Get alert statistics."""
    try:
        return await alert_repository.get_alerts_stats(session, days=days)
    except Exception as e:
        logger.log_error("Failed to get alert statistics", error=e)
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve alert statistics"
        )

@router.get("/{uuid}", response_model=AlertResponse)
async def get_alert(
    uuid: UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Alert:
    """Get alert by UUID."""
    try:
        alert = await alert_repository.get_by_uuid(session, uuid)
        if not alert:
            raise ResourceNotFoundError("Alert not found")
        return alert
    except Exception as e:
        logger.log_error("Failed to get alert", error=e, uuid=uuid)
        raise HTTPException(
            status_code=404,
            detail=f"Alert {uuid} not found"
        )

@router.put("/{uuid}", response_model=AlertResponse)
async def update_alert(
    uuid: UUID,
    alert_in: AlertUpdate,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Alert:
    """Update alert."""
    try:
        # Get alert
        alert = await alert_repository.get_by_uuid(session, uuid)
        if not alert:
            raise ResourceNotFoundError("Alert not found")
        
        # Update alert
        update_data = alert_in.dict(exclude_unset=True)
        if "status" in update_data:
            if update_data["status"] in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]:
                update_data["resolved_at"] = datetime.utcnow()
        
        alert = await alert_repository.update(
            session,
            db_obj=alert,
            obj_in=update_data
        )
        
        await session.commit()
        
        # Log alert update
        logger.log_info(
            "Alert updated",
            alert_id=alert.uuid,
            title=alert.title,
            status=alert.status
        )
        
        return alert
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to update alert", error=e, uuid=uuid)
        raise HTTPException(
            status_code=500,
            detail="Failed to update alert"
        )

@router.post("/{uuid}/assign", response_model=AlertResponse)
async def assign_alert(
    uuid: UUID,
    user_id: int,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Alert:
    """Assign alert to user."""
    try:
        # Get alert
        alert = await alert_repository.get_by_uuid(session, uuid)
        if not alert:
            raise ResourceNotFoundError("Alert not found")
        
        # Update alert
        alert = await alert_repository.update(
            session,
            db_obj=alert,
            obj_in={
                "assigned_to_id": user_id,
                "status": AlertStatus.IN_PROGRESS
            }
        )
        
        await session.commit()
        
        # Log alert assignment
        logger.log_info(
            "Alert assigned",
            alert_id=alert.uuid,
            title=alert.title,
            assigned_to=user_id
        )
        
        return alert
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to assign alert", error=e, uuid=uuid)
        raise HTTPException(
            status_code=500,
            detail="Failed to assign alert"
        )

@router.post("/{uuid}/resolve", response_model=AlertResponse)
async def resolve_alert(
    uuid: UUID,
    notes: Optional[str] = None,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Alert:
    """Resolve alert."""
    try:
        # Get alert
        alert = await alert_repository.get_by_uuid(session, uuid)
        if not alert:
            raise ResourceNotFoundError("Alert not found")
        
        # Update alert
        alert = await alert_repository.update(
            session,
            db_obj=alert,
            obj_in={
                "status": AlertStatus.RESOLVED,
                "resolution_notes": notes,
                "resolved_at": datetime.utcnow()
            }
        )
        
        await session.commit()
        
        # Log alert resolution
        logger.log_info(
            "Alert resolved",
            alert_id=alert.uuid,
            title=alert.title
        )
        
        return alert
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to resolve alert", error=e, uuid=uuid)
        raise HTTPException(
            status_code=500,
            detail="Failed to resolve alert"
        )

@router.post("/{uuid}/false-positive", response_model=AlertResponse)
async def mark_false_positive(
    uuid: UUID,
    reason: str,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Alert:
    """Mark alert as false positive."""
    try:
        # Get alert
        alert = await alert_repository.get_by_uuid(session, uuid)
        if not alert:
            raise ResourceNotFoundError("Alert not found")
        
        # Update alert
        alert = await alert_repository.update(
            session,
            db_obj=alert,
            obj_in={
                "status": AlertStatus.FALSE_POSITIVE,
                "false_positive_reason": reason,
                "resolved_at": datetime.utcnow()
            }
        )
        
        await session.commit()
        
        # Log false positive
        logger.log_info(
            "Alert marked as false positive",
            alert_id=alert.uuid,
            title=alert.title,
            reason=reason
        )
        
        return alert
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to mark alert as false positive", error=e, uuid=uuid)
        raise HTTPException(
            status_code=500,
            detail="Failed to mark alert as false positive"
        )

@router.delete("/{uuid}")
async def delete_alert(
    uuid: UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superuser)
) -> dict:
    """Delete alert."""
    try:
        # Get alert
        alert = await alert_repository.get_by_uuid(session, uuid)
        if not alert:
            raise ResourceNotFoundError("Alert not found")
        
        # Delete alert
        deleted = await alert_repository.delete(session, id=alert.id)
        
        await session.commit()
        
        if deleted:
            # Log alert deletion
            logger.log_info(
                "Alert deleted",
                alert_id=uuid,
                deleted_by=current_user.username
            )
            
            return {"message": "Alert deleted"}
        else:
            raise ResourceNotFoundError("Alert not found")
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to delete alert", error=e, uuid=uuid)
        raise HTTPException(
            status_code=500,
            detail="Failed to delete alert"
        ) 