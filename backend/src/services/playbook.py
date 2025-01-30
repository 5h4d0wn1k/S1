from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models.playbook import Playbook, PlaybookType, PlaybookStatus
from ..data.repositories.playbook import playbook_repository
from ..utils.logging import LoggerMixin
from ..core.exceptions import ResourceNotFoundError, ValidationError

class PlaybookService(LoggerMixin):
    """Service for handling playbook-related operations."""
    
    async def create_playbook(
        self,
        session: AsyncSession,
        data: Dict,
        author_id: int
    ) -> Playbook:
        """Create new playbook."""
        try:
            # Set initial values
            data["status"] = PlaybookStatus.DRAFT
            data["author_id"] = author_id
            data["version"] = "1.0.0"
            
            # Create playbook
            playbook = await playbook_repository.create(session, data)
            
            await session.commit()
            
            self.log_info(
                "Playbook created",
                playbook_id=playbook.uuid,
                name=playbook.name,
                type=playbook.type
            )
            
            return playbook
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to create playbook", error=e)
            raise
    
    async def get_playbook(
        self,
        session: AsyncSession,
        uuid: UUID
    ) -> Playbook:
        """Get playbook by UUID."""
        try:
            playbook = await playbook_repository.get_by_uuid(session, uuid)
            if not playbook:
                raise ResourceNotFoundError("Playbook not found")
            return playbook
            
        except ResourceNotFoundError:
            raise
        except Exception as e:
            self.log_error("Failed to get playbook", error=e, uuid=uuid)
            raise
    
    async def update_playbook(
        self,
        session: AsyncSession,
        uuid: UUID,
        data: Dict,
        updated_by: int
    ) -> Playbook:
        """Update playbook."""
        try:
            # Get playbook
            playbook = await self.get_playbook(session, uuid)
            
            # Validate status transition
            if "status" in data:
                await self._validate_status_transition(playbook, data["status"])
            
            # Update playbook
            playbook = await playbook_repository.update(
                session,
                db_obj=playbook,
                obj_in=data
            )
            
            await session.commit()
            
            self.log_info(
                "Playbook updated",
                playbook_id=playbook.uuid,
                name=playbook.name,
                status=playbook.status
            )
            
            return playbook
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to update playbook", error=e, uuid=uuid)
            raise
    
    async def delete_playbook(
        self,
        session: AsyncSession,
        uuid: UUID,
        deleted_by: int
    ) -> bool:
        """Delete playbook."""
        try:
            # Get playbook
            playbook = await self.get_playbook(session, uuid)
            
            # Delete playbook
            deleted = await playbook_repository.delete(session, id=playbook.id)
            
            await session.commit()
            
            if deleted:
                self.log_info(
                    "Playbook deleted",
                    playbook_id=uuid,
                    deleted_by=deleted_by
                )
                return True
            
            raise ResourceNotFoundError("Playbook not found")
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to delete playbook", error=e, uuid=uuid)
            raise
    
    async def publish_playbook(
        self,
        session: AsyncSession,
        uuid: UUID,
        version: Optional[str] = None,
        published_by: int = None
    ) -> Playbook:
        """Publish playbook."""
        try:
            # Get playbook
            playbook = await self.get_playbook(session, uuid)
            
            # Validate playbook can be published
            if not playbook.steps:
                raise ValidationError("Cannot publish playbook without steps")
            
            # Publish playbook
            playbook.publish(version)
            playbook = await playbook_repository.update(
                session,
                db_obj=playbook,
                obj_in={
                    "status": PlaybookStatus.ACTIVE,
                    "published_at": datetime.utcnow()
                }
            )
            
            await session.commit()
            
            self.log_info(
                "Playbook published",
                playbook_id=playbook.uuid,
                name=playbook.name,
                version=playbook.version
            )
            
            return playbook
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to publish playbook", error=e, uuid=uuid)
            raise
    
    async def deprecate_playbook(
        self,
        session: AsyncSession,
        uuid: UUID,
        reason: str,
        deprecated_by: int
    ) -> Playbook:
        """Deprecate playbook."""
        try:
            # Get playbook
            playbook = await self.get_playbook(session, uuid)
            
            # Deprecate playbook
            playbook.deprecate(reason)
            playbook = await playbook_repository.update(
                session,
                db_obj=playbook,
                obj_in={"status": PlaybookStatus.DEPRECATED}
            )
            
            await session.commit()
            
            self.log_info(
                "Playbook deprecated",
                playbook_id=playbook.uuid,
                name=playbook.name,
                reason=reason
            )
            
            return playbook
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to deprecate playbook", error=e, uuid=uuid)
            raise
    
    async def add_step(
        self,
        session: AsyncSession,
        uuid: UUID,
        title: str,
        description: str,
        step_type: str,
        automation: Optional[dict] = None,
        metadata: Optional[dict] = None,
        added_by: int = None
    ) -> Playbook:
        """Add step to playbook."""
        try:
            # Get playbook
            playbook = await self.get_playbook(session, uuid)
            
            # Add step
            playbook.add_step(
                title=title,
                description=description,
                step_type=step_type,
                automation=automation,
                metadata=metadata
            )
            
            # Update playbook
            playbook = await playbook_repository.update(
                session,
                db_obj=playbook,
                obj_in={"steps": playbook.steps}
            )
            
            await session.commit()
            
            self.log_info(
                "Step added to playbook",
                playbook_id=playbook.uuid,
                name=playbook.name,
                step_title=title
            )
            
            return playbook
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to add step to playbook", error=e, uuid=uuid)
            raise
    
    async def update_step(
        self,
        session: AsyncSession,
        uuid: UUID,
        step_id: int,
        data: Dict,
        updated_by: int
    ) -> Playbook:
        """Update playbook step."""
        try:
            # Get playbook
            playbook = await self.get_playbook(session, uuid)
            
            # Update step
            playbook.update_step(step_id, **data)
            
            # Update playbook
            playbook = await playbook_repository.update(
                session,
                db_obj=playbook,
                obj_in={"steps": playbook.steps}
            )
            
            await session.commit()
            
            self.log_info(
                "Playbook step updated",
                playbook_id=playbook.uuid,
                name=playbook.name,
                step_id=step_id
            )
            
            return playbook
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to update playbook step", error=e, uuid=uuid)
            raise
    
    async def remove_step(
        self,
        session: AsyncSession,
        uuid: UUID,
        step_id: int,
        removed_by: int
    ) -> Playbook:
        """Remove step from playbook."""
        try:
            # Get playbook
            playbook = await self.get_playbook(session, uuid)
            
            # Remove step
            playbook.remove_step(step_id)
            
            # Update playbook
            playbook = await playbook_repository.update(
                session,
                db_obj=playbook,
                obj_in={"steps": playbook.steps}
            )
            
            await session.commit()
            
            self.log_info(
                "Step removed from playbook",
                playbook_id=playbook.uuid,
                name=playbook.name,
                step_id=step_id
            )
            
            return playbook
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to remove step from playbook", error=e, uuid=uuid)
            raise
    
    async def get_playbooks(
        self,
        session: AsyncSession,
        *,
        type: Optional[PlaybookType] = None,
        status: Optional[PlaybookStatus] = None,
        author_id: Optional[int] = None,
        tags: Optional[List[str]] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Playbook]:
        """Get playbooks with filters."""
        try:
            if type:
                return await playbook_repository.get_playbooks_by_type(
                    session,
                    type,
                    skip=skip,
                    limit=limit
                )
            elif status:
                return await playbook_repository.get_playbooks_by_status(
                    session,
                    status,
                    skip=skip,
                    limit=limit
                )
            elif author_id:
                return await playbook_repository.get_playbooks_by_author(
                    session,
                    author_id,
                    skip=skip,
                    limit=limit
                )
            elif tags:
                return await playbook_repository.get_playbooks_by_tags(
                    session,
                    tags,
                    skip=skip,
                    limit=limit
                )
            else:
                return await playbook_repository.get_all(
                    session,
                    skip=skip,
                    limit=limit
                )
                
        except Exception as e:
            self.log_error("Failed to get playbooks", error=e)
            raise
    
    async def get_active_playbooks(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Playbook]:
        """Get active playbooks."""
        try:
            return await playbook_repository.get_active_playbooks(
                session,
                skip=skip,
                limit=limit
            )
        except Exception as e:
            self.log_error("Failed to get active playbooks", error=e)
            raise
    
    async def get_playbook_stats(
        self,
        session: AsyncSession
    ) -> dict:
        """Get playbook statistics."""
        try:
            return await playbook_repository.get_playbooks_stats(session)
        except Exception as e:
            self.log_error("Failed to get playbook statistics", error=e)
            raise
    
    async def _validate_status_transition(
        self,
        playbook: Playbook,
        new_status: PlaybookStatus
    ) -> None:
        """Validate playbook status transition."""
        valid_transitions = {
            PlaybookStatus.DRAFT: [PlaybookStatus.ACTIVE],
            PlaybookStatus.ACTIVE: [PlaybookStatus.DEPRECATED, PlaybookStatus.ARCHIVED],
            PlaybookStatus.DEPRECATED: [PlaybookStatus.ARCHIVED],
            PlaybookStatus.ARCHIVED: []
        }
        
        if new_status not in valid_transitions.get(playbook.status, []):
            raise ValidationError(
                f"Invalid status transition from {playbook.status} to {new_status}"
            )

# Create service instance
playbook_service = PlaybookService() 