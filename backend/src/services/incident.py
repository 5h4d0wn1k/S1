from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentCategory
from ..data.repositories.incident import incident_repository
from ..utils.logging import LoggerMixin
from ..core.exceptions import ResourceNotFoundError

class IncidentService(LoggerMixin):
    """Service for handling incident-related operations."""
    
    async def create_incident(
        self,
        session: AsyncSession,
        data: Dict,
        created_by: str
    ) -> Incident:
        """Create new incident."""
        try:
            # Set initial values
            data["status"] = IncidentStatus.NEW
            data["detected_at"] = datetime.utcnow()
            data["indicators"] = {}
            data["timeline"] = []
            
            # Create incident
            incident = await incident_repository.create(session, data)
            
            # Add initial timeline event
            incident.add_timeline_event(
                "incident_created",
                f"Incident created by {created_by}",
                {"created_by": created_by}
            )
            
            await session.commit()
            
            self.log_info(
                "Incident created",
                incident_id=incident.uuid,
                title=incident.title,
                severity=incident.severity,
                category=incident.category
            )
            
            return incident
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to create incident", error=e)
            raise
    
    async def get_incident(
        self,
        session: AsyncSession,
        uuid: UUID
    ) -> Incident:
        """Get incident by UUID."""
        try:
            incident = await incident_repository.get_by_uuid(session, uuid)
            if not incident:
                raise ResourceNotFoundError("Incident not found")
            return incident
            
        except ResourceNotFoundError:
            raise
        except Exception as e:
            self.log_error("Failed to get incident", error=e, uuid=uuid)
            raise
    
    async def update_incident(
        self,
        session: AsyncSession,
        uuid: UUID,
        data: Dict,
        updated_by: str
    ) -> Incident:
        """Update incident."""
        try:
            # Get incident
            incident = await self.get_incident(session, uuid)
            
            # Handle status changes
            if "status" in data:
                old_status = incident.status
                new_status = data["status"]
                
                if new_status != old_status:
                    if new_status == IncidentStatus.CONTAINED:
                        data["contained_at"] = datetime.utcnow()
                    elif new_status == IncidentStatus.CLOSED:
                        data["resolved_at"] = datetime.utcnow()
                    
                    incident.add_timeline_event(
                        "status_change",
                        f"Status changed from {old_status} to {new_status}",
                        {
                            "old_status": old_status,
                            "new_status": new_status,
                            "changed_by": updated_by
                        }
                    )
            
            # Update incident
            incident = await incident_repository.update(
                session,
                db_obj=incident,
                obj_in=data
            )
            
            await session.commit()
            
            self.log_info(
                "Incident updated",
                incident_id=incident.uuid,
                title=incident.title,
                status=incident.status
            )
            
            return incident
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to update incident", error=e, uuid=uuid)
            raise
    
    async def delete_incident(
        self,
        session: AsyncSession,
        uuid: UUID,
        deleted_by: str
    ) -> bool:
        """Delete incident."""
        try:
            # Get incident
            incident = await self.get_incident(session, uuid)
            
            # Delete incident
            deleted = await incident_repository.delete(session, id=incident.id)
            
            await session.commit()
            
            if deleted:
                self.log_info(
                    "Incident deleted",
                    incident_id=uuid,
                    deleted_by=deleted_by
                )
                return True
            
            raise ResourceNotFoundError("Incident not found")
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to delete incident", error=e, uuid=uuid)
            raise
    
    async def assign_incident(
        self,
        session: AsyncSession,
        uuid: UUID,
        user_id: int,
        assigned_by: str
    ) -> Incident:
        """Assign incident to user."""
        try:
            # Get incident
            incident = await self.get_incident(session, uuid)
            
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
                    "assigned_by": assigned_by,
                    "assigned_to": user_id
                }
            )
            
            await session.commit()
            
            self.log_info(
                "Incident assigned",
                incident_id=incident.uuid,
                title=incident.title,
                lead_id=user_id
            )
            
            return incident
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to assign incident", error=e, uuid=uuid)
            raise
    
    async def add_team_member(
        self,
        session: AsyncSession,
        uuid: UUID,
        user_id: int,
        added_by: str
    ) -> Incident:
        """Add team member to incident."""
        try:
            # Get incident
            incident = await self.get_incident(session, uuid)
            
            # Add team member
            incident.add_team_member(user_id)
            
            # Add timeline event
            incident.add_timeline_event(
                "team_member_added",
                f"Team member {user_id} added to incident",
                {
                    "added_by": added_by,
                    "user_id": user_id
                }
            )
            
            await session.commit()
            
            self.log_info(
                "Team member added",
                incident_id=incident.uuid,
                title=incident.title,
                user_id=user_id
            )
            
            return incident
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to add team member", error=e, uuid=uuid)
            raise
    
    async def remove_team_member(
        self,
        session: AsyncSession,
        uuid: UUID,
        user_id: int,
        removed_by: str
    ) -> Incident:
        """Remove team member from incident."""
        try:
            # Get incident
            incident = await self.get_incident(session, uuid)
            
            # Remove team member
            incident.remove_team_member(user_id)
            
            # Add timeline event
            incident.add_timeline_event(
                "team_member_removed",
                f"Team member {user_id} removed from incident",
                {
                    "removed_by": removed_by,
                    "user_id": user_id
                }
            )
            
            await session.commit()
            
            self.log_info(
                "Team member removed",
                incident_id=incident.uuid,
                title=incident.title,
                user_id=user_id
            )
            
            return incident
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to remove team member", error=e, uuid=uuid)
            raise
    
    async def add_timeline_event(
        self,
        session: AsyncSession,
        uuid: UUID,
        event_type: str,
        description: str,
        metadata: Optional[dict] = None,
        added_by: str = None
    ) -> Incident:
        """Add timeline event to incident."""
        try:
            # Get incident
            incident = await self.get_incident(session, uuid)
            
            # Add timeline event
            incident.add_timeline_event(
                event_type,
                description,
                {
                    **(metadata or {}),
                    "added_by": added_by
                }
            )
            
            await session.commit()
            
            self.log_info(
                "Timeline event added",
                incident_id=incident.uuid,
                title=incident.title,
                event_type=event_type
            )
            
            return incident
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to add timeline event", error=e, uuid=uuid)
            raise
    
    async def get_incidents(
        self,
        session: AsyncSession,
        *,
        severity: Optional[IncidentSeverity] = None,
        status: Optional[IncidentStatus] = None,
        category: Optional[IncidentCategory] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100
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
            self.log_error("Failed to get incidents", error=e)
            raise
    
    async def get_active_incidents(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Incident]:
        """Get active incidents."""
        try:
            return await incident_repository.get_active_incidents(
                session,
                skip=skip,
                limit=limit
            )
        except Exception as e:
            self.log_error("Failed to get active incidents", error=e)
            raise
    
    async def get_incident_stats(
        self,
        session: AsyncSession,
        days: int = 30
    ) -> dict:
        """Get incident statistics."""
        try:
            return await incident_repository.get_incidents_stats(session, days=days)
        except Exception as e:
            self.log_error("Failed to get incident statistics", error=e)
            raise

# Create service instance
incident_service = IncidentService() 