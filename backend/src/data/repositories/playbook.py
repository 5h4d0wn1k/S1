from typing import List, Optional
from datetime import datetime

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from .base import BaseRepository
from ..models.playbook import Playbook, PlaybookType, PlaybookStatus

class PlaybookRepository(BaseRepository[Playbook]):
    """Playbook repository."""
    
    def __init__(self) -> None:
        """Initialize repository."""
        super().__init__(Playbook)
    
    async def get_by_name(
        self,
        session: AsyncSession,
        name: str
    ) -> Optional[Playbook]:
        """Get playbook by name."""
        try:
            stmt = self.select().where(Playbook.name == name)
            result = await session.execute(stmt)
            return result.scalar_one_or_none()
        except Exception as e:
            self.log_error(
                "Failed to get playbook by name",
                error=e,
                name=name
            )
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
            stmt = (
                self.select()
                .where(Playbook.status == PlaybookStatus.ACTIVE)
                .order_by(Playbook.name)
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get active playbooks",
                error=e,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_playbooks_by_type(
        self,
        session: AsyncSession,
        type: PlaybookType,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Playbook]:
        """Get playbooks by type."""
        try:
            stmt = (
                self.select()
                .where(Playbook.type == type)
                .order_by(Playbook.name)
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get playbooks by type",
                error=e,
                type=type,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_playbooks_by_status(
        self,
        session: AsyncSession,
        status: PlaybookStatus,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Playbook]:
        """Get playbooks by status."""
        try:
            stmt = (
                self.select()
                .where(Playbook.status == status)
                .order_by(Playbook.name)
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get playbooks by status",
                error=e,
                status=status,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_playbooks_by_author(
        self,
        session: AsyncSession,
        author_id: int,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Playbook]:
        """Get playbooks by author."""
        try:
            stmt = (
                self.select()
                .where(Playbook.author_id == author_id)
                .order_by(Playbook.name)
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get playbooks by author",
                error=e,
                author_id=author_id,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_playbooks_by_tags(
        self,
        session: AsyncSession,
        tags: List[str],
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Playbook]:
        """Get playbooks by tags."""
        try:
            stmt = (
                self.select()
                .where(Playbook.tags.contains(tags))
                .order_by(Playbook.name)
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get playbooks by tags",
                error=e,
                tags=tags,
                skip=skip,
                limit=limit
            )
            raise
    
    async def search_playbooks(
        self,
        session: AsyncSession,
        query: str,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Playbook]:
        """Search playbooks by name or description."""
        try:
            stmt = (
                self.select()
                .where(
                    or_(
                        Playbook.name.ilike(f"%{query}%"),
                        Playbook.description.ilike(f"%{query}%")
                    )
                )
                .order_by(Playbook.name)
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to search playbooks",
                error=e,
                query=query,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_playbooks_stats(self, session: AsyncSession) -> dict:
        """Get playbook statistics."""
        try:
            # Get total counts by type
            type_stmt = (
                select(Playbook.type, func.count(Playbook.id))
                .group_by(Playbook.type)
            )
            type_result = await session.execute(type_stmt)
            type_stats = dict(type_result.all())
            
            # Get total counts by status
            status_stmt = (
                select(Playbook.status, func.count(Playbook.id))
                .group_by(Playbook.status)
            )
            status_result = await session.execute(status_stmt)
            status_stats = dict(status_result.all())
            
            # Get automation coverage
            automation_stmt = (
                select(
                    func.count(Playbook.id),
                    func.count(Playbook.automation)
                )
                .where(Playbook.automation != {})
            )
            automation_result = await session.execute(automation_stmt)
            total, automated = automation_result.first()
            
            return {
                "type": type_stats,
                "status": status_stats,
                "total": sum(type_stats.values()),
                "automation_coverage": (automated / total) if total > 0 else 0
            }
        except Exception as e:
            self.log_error("Failed to get playbook statistics", error=e)
            raise

# Create repository instance
playbook_repository = PlaybookRepository() 