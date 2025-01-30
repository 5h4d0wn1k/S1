from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.log import LogEntry, LogSource, LogType
from .base import BaseRepository

class LogSourceRepository(BaseRepository[LogSource, LogSource, LogSource]):
    """Repository for log sources."""
    
    def __init__(self):
        """Initialize repository with LogSource model."""
        super().__init__(LogSource)
    
    async def get_active_sources(
        self,
        session: AsyncSession
    ) -> List[LogSource]:
        """Get active log sources."""
        result = await session.execute(
            select(self.model)
            .where(self.model.status == "active")
        )
        return result.scalars().all()
    
    async def get_source_by_name(
        self,
        session: AsyncSession,
        name: str
    ) -> Optional[LogSource]:
        """Get log source by name."""
        result = await session.execute(
            select(self.model)
            .where(self.model.name == name)
        )
        return result.scalar_one_or_none()
    
    async def get_sources_by_type(
        self,
        session: AsyncSession,
        source_type: str
    ) -> List[LogSource]:
        """Get log sources by type."""
        result = await session.execute(
            select(self.model)
            .where(self.model.type == source_type)
        )
        return result.scalars().all()
    
    async def get_source_counts_by_type(
        self,
        session: AsyncSession
    ) -> dict:
        """Get source counts by type."""
        result = await session.execute(
            select(self.model.type, self.model.id)
        )
        counts = {}
        for row in result:
            source_type = row[0]
            counts[source_type] = counts.get(source_type, 0) + 1
        return counts

class LogEntryRepository(BaseRepository[LogEntry, LogEntry, LogEntry]):
    """Repository for log entries."""
    
    def __init__(self):
        """Initialize repository with LogEntry model."""
        super().__init__(LogEntry)
    
    async def get_logs_by_source(
        self,
        session: AsyncSession,
        source_id: UUID,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[LogEntry]:
        """Get logs by source ID."""
        result = await session.execute(
            select(self.model)
            .where(self.model.source_id == source_id)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_logs_by_type(
        self,
        session: AsyncSession,
        log_type: LogType,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[LogEntry]:
        """Get logs by type."""
        result = await session.execute(
            select(self.model)
            .where(self.model.log_type == log_type)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_logs_by_timerange(
        self,
        session: AsyncSession,
        start_time: datetime,
        end_time: datetime,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[LogEntry]:
        """Get logs within time range."""
        result = await session.execute(
            select(self.model)
            .where(
                and_(
                    self.model.timestamp >= start_time,
                    self.model.timestamp <= end_time
                )
            )
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_logs_by_host(
        self,
        session: AsyncSession,
        host: str,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[LogEntry]:
        """Get logs by host."""
        result = await session.execute(
            select(self.model)
            .where(self.model.host == host)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_logs_by_ip(
        self,
        session: AsyncSession,
        ip_address: str,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[LogEntry]:
        """Get logs by IP address."""
        result = await session.execute(
            select(self.model)
            .where(self.model.ip_address == ip_address)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_logs_by_user(
        self,
        session: AsyncSession,
        user: str,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[LogEntry]:
        """Get logs by user."""
        result = await session.execute(
            select(self.model)
            .where(self.model.user == user)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_log_count_by_type(
        self,
        session: AsyncSession
    ) -> dict:
        """Get log counts by type."""
        result = await session.execute(
            select(self.model.log_type, self.model.id)
        )
        counts = {}
        for row in result:
            log_type = row[0]
            counts[log_type] = counts.get(log_type, 0) + 1
        return counts
    
    async def get_log_count_by_source(
        self,
        session: AsyncSession
    ) -> dict:
        """Get log counts by source."""
        result = await session.execute(
            select(self.model.source_id, self.model.id)
        )
        counts = {}
        for row in result:
            source_id = str(row[0])
            counts[source_id] = counts.get(source_id, 0) + 1
        return counts
    
    async def get_log_count_today(
        self,
        session: AsyncSession
    ) -> int:
        """Get log count for today."""
        today = datetime.utcnow().date()
        result = await session.execute(
            select(self.model.id)
            .where(
                and_(
                    self.model.timestamp >= today,
                    self.model.timestamp < today + timedelta(days=1)
                )
            )
        )
        return len(result.scalars().all())

# Create repository instances
log_source_repository = LogSourceRepository()
log_entry_repository = LogEntryRepository() 