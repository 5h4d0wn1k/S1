from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...data.db import get_db
from ...data.repositories.incident import incident_repository
from ...data.models.incident import (
    Incident,
    IncidentSeverity,
    IncidentStatus,
    IncidentCategory
)
from ..auth import get_current_active_user, check_permission
from ..exceptions import ResourceNotFoundError
from ...utils.logging import LoggerMixin

router = APIRouter()
logger = LoggerMixin()

class IncidentCreate(BaseModel):
    """Incident creation model."""
    title: str
    description: str
    severity: IncidentSeverity
    category: IncidentCategory
    tags: List[str] = []
    affected_systems: List[str] = []
    affected_users: List[str] = []
    business_impact: Optional[str] = None
    data_breach: bool = False
    attack_vector: Optional[str] = None
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []
    playbook_id: Optional[int] = None

class IncidentUpdate(BaseModel):
    """Incident update model."""
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    category: Optional[IncidentCategory] = None
    tags: Optional[List[str]] = None
    affected_systems: Optional[List[str]] = None
    affected_users: Optional[List[str]] = None
    business_impact: Optional[str] = None
    data_breach: Optional[bool] = None
    root_cause: Optional[str] = None
    attack_vector: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    containment_strategy: Optional[str] = None
    eradication_steps: Optional[str] = None
    recovery_steps: Optional[str] = None
    lessons_learned: Optional[str] = None
    playbook_id: Optional[int] = None

class IncidentResponse(BaseModel):
    """Incident response model."""
    uuid: UUID
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    category: IncidentCategory
    tags: List[str]
    affected_systems: List[str]
    affected_users: List[str]
    business_impact: Optional[str]
    data_breach: bool
    detected_at: datetime
    contained_at: Optional[datetime]
    resolved_at: Optional[datetime]
    root_cause: Optional[str]
    attack_vector: Optional[str]
    indicators: dict
    timeline: List[dict]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    playbook_id: Optional[int]
    containment_strategy: Optional[str]
    eradication_steps: Optional[str]
    recovery_steps: Optional[str]
    lessons_learned: Optional[str]
    lead: Optional[str]
    team_members: List[str]
    alerts: List[dict]
    created_at: datetime
    updated_at: datetime

@router.post("", response_model=IncidentResponse)
async def create_incident(
    incident_in: IncidentCreate,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Incident:
    """Create new incident."""
    try:
        # Create incident
        incident = await incident_repository.create(
            session,
            {
                **incident_in.dict(),
                "status": IncidentStatus.NEW,
                "detected_at": datetime.utcnow(),
                "indicators": {},
                "timeline": []
            }
        )
        
        # Add initial timeline event
        incident.add_timeline_event(
            "incident_created",
            f"Incident created by {current_user.username}",
            {"created_by": current_user.username}
        )
        
        await session.commit()
        
        # Log incident creation
        logger.log_info(
            "Incident created",
            incident_id=incident.uuid,
            title=incident.title,
            severity=incident.severity,
            category=incident.category
        )
        
        return incident
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to create incident", error=e)
        raise

@router.get("", response_model=List[IncidentResponse])
async def get_incidents(
    severity: Optional[IncidentSeverity] = None,
    status: Optional[IncidentStatus] = None,
    category: Optional[IncidentCategory] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> List[Incident]:
    """Get incidents with filters."""
    try:
        if severity:
            return await incident_repository.get_incidents_by_severity(
                session,
                severity,
                skip=skip,
                limit=limit
            )
        elif status:
            return await incident_repository.get_incidents_by_status(
                session,
                status,
                skip=skip,
                limit=limit
            )
        elif category:
            return await incident_repository.get_incidents_by_category(
                session,
                category,
                skip=skip,
                limit=limit
            )
        elif start_time and end_time:
            return await incident_repository.get_incidents_by_timerange(
                session,
                start_time,
                end_time,
                skip=skip,
                limit=limit
            )
        else:
            return await incident_repository.get_all(
                session,
                skip=skip,
                limit=limit
            )
    except Exception as e:
        logger.log_error("Failed to get incidents", error=e)
        raise

@router.get("/active", response_model=List[IncidentResponse])
async def get_active_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> List[Incident]:
    """Get active incidents."""
    try:
        return await incident_repository.get_active_incidents(
            session,
            skip=skip,
            limit=limit
        )
    except Exception as e:
        logger.log_error("Failed to get active incidents", error=e)
        raise

@router.get("/stats")
async def get_incident_stats(
    days: int = Query(30, ge=1, le=365),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> dict:
    """Get incident statistics."""
    try:
        return await incident_repository.get_incidents_stats(session, days=days)
    except Exception as e:
        logger.log_error("Failed to get incident statistics", error=e)
        raise

@router.get("/{uuid}", response_model=IncidentResponse)
async def get_incident(
    uuid: UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Incident:
    """Get incident by UUID."""
    try:
        incident = await incident_repository.get_by_uuid(session, uuid)
        if not incident:
            raise ResourceNotFoundError("Incident not found")
        return incident
    except Exception as e:
        logger.log_error("Failed to get incident", error=e, uuid=uuid)
        raise

@router.put("/{uuid}", response_model=IncidentResponse)
async def update_incident(
    uuid: UUID,
    incident_in: IncidentUpdate,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Incident:
    """Update incident."""
    try:
        # Get incident
        incident = await incident_repository.get_by_uuid(session, uuid)
        if not incident:
            raise ResourceNotFoundError("Incident not found")
        
        # Update incident
        update_data = incident_in.dict(exclude_unset=True)
        if "status" in update_data:
            old_status = incident.status
            new_status = update_data["status"]
            
            if new_status != old_status:
                if new_status == IncidentStatus.CONTAINED:
                    update_data["contained_at"] = datetime.utcnow()
                elif new_status == IncidentStatus.CLOSED:
                    update_data["resolved_at"] = datetime.utcnow()
                
                incident.add_timeline_event(
                    "status_change",
                    f"Status changed from {old_status} to {new_status}",
                    {
                        "old_status": old_status,
                        "new_status": new_status,
                        "changed_by": current_user.username
                    }
                )
        
        incident = await incident_repository.update(
            session,
            db_obj=incident,
            obj_in=update_data
        )
        
        await session.commit()
        
        # Log incident update
        logger.log_info(
            "Incident updated",
            incident_id=incident.uuid,
            title=incident.title,
            status=incident.status
        )
        
        return incident
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to update incident", error=e, uuid=uuid)
        raise

@router.post("/{uuid}/assign", response_model=IncidentResponse)
async def assign_incident(
    uuid: UUID,
    user_id: int,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Incident:
    """Assign incident to user."""
    try:
        # Get incident
        incident = await incident_repository.get_by_uuid(session, uuid)
        if not incident:
            raise ResourceNotFoundError("Incident not found")
        
        # Update incident
        incident = await incident_repository.update(
            session,
            db_obj=incident,
            obj_in={"lead_id": user_id}
        )
        
        # Add timeline event
        incident.add_timeline_event(
            "lead_assigned",
            f"Incident lead assigned to user {user_id}",
            {
                "assigned_by": current_user.username,
                "assigned_to": user_id
            }
        )
        
        await session.commit()
        
        # Log incident assignment
        logger.log_info(
            "Incident assigned",
            incident_id=incident.uuid,
            title=incident.title,
            lead_id=user_id
        )
        
        return incident
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to assign incident", error=e, uuid=uuid)
        raise

@router.post("/{uuid}/team/add", response_model=IncidentResponse)
async def add_team_member(
    uuid: UUID,
    user_id: int,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Incident:
    """Add team member to incident."""
    try:
        # Get incident
        incident = await incident_repository.get_by_uuid(session, uuid)
        if not incident:
            raise ResourceNotFoundError("Incident not found")
        
        # Add team member
        incident.add_team_member(user_id)
        
        # Add timeline event
        incident.add_timeline_event(
            "team_member_added",
            f"Team member {user_id} added to incident",
            {
                "added_by": current_user.username,
                "user_id": user_id
            }
        )
        
        await session.commit()
        
        # Log team member addition
        logger.log_info(
            "Team member added",
            incident_id=incident.uuid,
            title=incident.title,
            user_id=user_id
        )
        
        return incident
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to add team member", error=e, uuid=uuid)
        raise

@router.post("/{uuid}/team/remove", response_model=IncidentResponse)
async def remove_team_member(
    uuid: UUID,
    user_id: int,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Incident:
    """Remove team member from incident."""
    try:
        # Get incident
        incident = await incident_repository.get_by_uuid(session, uuid)
        if not incident:
            raise ResourceNotFoundError("Incident not found")
        
        # Remove team member
        incident.remove_team_member(user_id)
        
        # Add timeline event
        incident.add_timeline_event(
            "team_member_removed",
            f"Team member {user_id} removed from incident",
            {
                "removed_by": current_user.username,
                "user_id": user_id
            }
        )
        
        await session.commit()
        
        # Log team member removal
        logger.log_info(
            "Team member removed",
            incident_id=incident.uuid,
            title=incident.title,
            user_id=user_id
        )
        
        return incident
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to remove team member", error=e, uuid=uuid)
        raise

@router.post("/{uuid}/timeline", response_model=IncidentResponse)
async def add_timeline_event(
    uuid: UUID,
    event_type: str,
    description: str,
    metadata: Optional[dict] = None,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Incident:
    """Add timeline event to incident."""
    try:
        # Get incident
        incident = await incident_repository.get_by_uuid(session, uuid)
        if not incident:
            raise ResourceNotFoundError("Incident not found")
        
        # Add timeline event
        incident.add_timeline_event(
            event_type,
            description,
            {
                **(metadata or {}),
                "added_by": current_user.username
            }
        )
        
        await session.commit()
        
        # Log timeline event addition
        logger.log_info(
            "Timeline event added",
            incident_id=incident.uuid,
            title=incident.title,
            event_type=event_type
        )
        
        return incident
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to add timeline event", error=e, uuid=uuid)
        raise

@router.delete("/{uuid}")
async def delete_incident(
    uuid: UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superuser)
) -> dict:
    """Delete incident."""
    try:
        # Get incident
        incident = await incident_repository.get_by_uuid(session, uuid)
        if not incident:
            raise ResourceNotFoundError("Incident not found")
        
        # Delete incident
        deleted = await incident_repository.delete(session, id=incident.id)
        
        await session.commit()
        
        if deleted:
            # Log incident deletion
            logger.log_info(
                "Incident deleted",
                incident_id=uuid,
                deleted_by=current_user.username
            )
            
            return {"message": "Incident deleted"}
        else:
            raise ResourceNotFoundError("Incident not found")
    except Exception as e:
        await session.rollback()
        logger.log_error("Failed to delete incident", error=e, uuid=uuid)
        raise 