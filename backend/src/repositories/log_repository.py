from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from ..models.log import (
    LogSource,
    LogEntry,
    LogBatch,
    LogSourceMetrics,
    LogType,
    LogLevel,
    LogSourceType,
    LogSourceStatus
)
from .base import BaseRepository
from ..utils.logging import LoggerMixin
from ..core.exceptions import DatabaseError

class LogSourceRepository(BaseRepository[LogSource], LoggerMixin):
    """Repository for managing log sources."""

    def __init__(self):
        """Initialize the repository with LogSource model."""
        super().__init__(LogSource)
        self.logger.info("Initialized LogSourceRepository")

    async def get_active_sources(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[LogSource]:
        """Get active log sources with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.status == LogSourceStatus.ACTIVE)
                .offset(skip)
                .limit(limit)
            )
            sources = result.scalars().all()
            self.logger.debug(f"Retrieved {len(sources)} active log sources")
            return sources
        except SQLAlchemyError as e:
            error_msg = f"Failed to get active log sources: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

    async def get_sources_by_type(
        self,
        session: AsyncSession,
        source_type: LogSourceType,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[LogSource]:
        """Get log sources by type with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.type == source_type)
                .offset(skip)
                .limit(limit)
            )
            sources = result.scalars().all()
            self.logger.debug(f"Retrieved {len(sources)} sources of type {source_type}")
            return sources
        except SQLAlchemyError as e:
            error_msg = f"Failed to get log sources by type {source_type}: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

    async def get_sources_with_errors(
        self,
        session: AsyncSession,
        min_error_count: int = 1,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[LogSource]:
        """Get log sources with error conditions."""
        try:
            result = await session.execute(
                select(self.model)
                .where(
                    or_(
                        self.model.status == LogSourceStatus.ERROR,
                        self.model.error_count >= min_error_count
                    )
                )
                .order_by(self.model.error_count.desc())
                .offset(skip)
                .limit(limit)
            )
            sources = result.scalars().all()
            self.logger.debug(f"Retrieved {len(sources)} sources with errors")
            return sources
        except SQLAlchemyError as e:
            error_msg = "Failed to get log sources with errors"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def update_source_status(
        self,
        session: AsyncSession,
        source_id: UUID,
        status: LogSourceStatus,
        error_message: Optional[str] = None
    ) -> LogSource:
        """Update log source status and error information."""
        try:
            source = await self.get(session, source_id)
            if not source:
                error_msg = f"Log source {source_id} not found"
                self.logger.error(error_msg)
                raise DatabaseError(error_msg)

            source.status = status
            source.error_message = error_message
            if status == LogSourceStatus.ERROR:
                source.error_count += 1
            elif status == LogSourceStatus.ACTIVE:
                source.error_count = 0

            session.add(source)
            await session.commit()
            await session.refresh(source)

            self.logger.info(f"Updated status of log source {source_id} to {status}")
            return source
        except SQLAlchemyError as e:
            error_msg = f"Failed to update log source status: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

class LogEntryRepository(BaseRepository[LogEntry], LoggerMixin):
    """Repository for managing log entries."""

    def __init__(self):
        """Initialize the repository with LogEntry model."""
        super().__init__(LogEntry)
        self.logger.info("Initialized LogEntryRepository")

    async def get_logs_by_source(
        self,
        session: AsyncSession,
        source_id: UUID,
        *,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        log_level: Optional[LogLevel] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[LogEntry]:
        """Get logs by source with optional filters."""
        try:
            query = select(self.model).where(self.model.source_id == source_id)

            if start_time:
                query = query.where(self.model.timestamp >= start_time)
            if end_time:
                query = query.where(self.model.timestamp <= end_time)
            if log_level:
                query = query.where(self.model.level == log_level)

            result = await session.execute(
                query
                .order_by(self.model.timestamp.desc())
                .offset(skip)
                .limit(limit)
            )
            logs = result.scalars().all()
            self.logger.debug(f"Retrieved {len(logs)} logs for source {source_id}")
            return logs
        except SQLAlchemyError as e:
            error_msg = f"Failed to get logs for source {source_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_logs_by_criteria(
        self,
        session: AsyncSession,
        *,
        source_ids: Optional[List[UUID]] = None,
        log_types: Optional[List[LogType]] = None,
        log_levels: Optional[List[LogLevel]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        host: Optional[str] = None,
        ip_address: Optional[str] = None,
        user: Optional[str] = None,
        process: Optional[str] = None,
        correlation_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[LogEntry]:
        """Get logs by multiple criteria with pagination."""
        try:
            conditions = []

            if source_ids:
                conditions.append(self.model.source_id.in_(source_ids))
            if log_types:
                conditions.append(self.model.log_type.in_(log_types))
            if log_levels:
                conditions.append(self.model.level.in_(log_levels))
            if start_time:
                conditions.append(self.model.timestamp >= start_time)
            if end_time:
                conditions.append(self.model.timestamp <= end_time)
            if host:
                conditions.append(self.model.host == host)
            if ip_address:
                conditions.append(self.model.ip_address == ip_address)
            if user:
                conditions.append(self.model.user == user)
            if process:
                conditions.append(self.model.process == process)
            if correlation_id:
                conditions.append(self.model.correlation_id == correlation_id)

            query = select(self.model)
            if conditions:
                query = query.where(and_(*conditions))

            result = await session.execute(
                query
                .order_by(self.model.timestamp.desc())
                .offset(skip)
                .limit(limit)
            )
            logs = result.scalars().all()
            self.logger.debug(f"Retrieved {len(logs)} logs matching criteria")
            return logs
        except SQLAlchemyError as e:
            error_msg = "Failed to get logs by criteria"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_log_statistics(
        self,
        session: AsyncSession,
        timeframe_minutes: int = 60
    ) -> Dict[str, Any]:
        """Get log statistics for the specified timeframe."""
        try:
            start_time = datetime.utcnow() - timedelta(minutes=timeframe_minutes)
            
            # Get counts by log type
            type_counts = await session.execute(
                select(
                    self.model.log_type,
                    func.count(self.model.id)
                )
                .where(self.model.timestamp >= start_time)
                .group_by(self.model.log_type)
            )
            
            # Get counts by severity
            severity_counts = await session.execute(
                select(
                    self.model.level,
                    func.count(self.model.id)
                )
                .where(self.model.timestamp >= start_time)
                .group_by(self.model.level)
            )
            
            # Get counts by source
            source_counts = await session.execute(
                select(
                    self.model.source_id,
                    func.count(self.model.id)
                )
                .where(self.model.timestamp >= start_time)
                .group_by(self.model.source_id)
            )

            return {
                "log_types": dict(type_counts.all()),
                "severity_levels": dict(severity_counts.all()),
                "sources": dict(source_counts.all()),
                "timeframe_minutes": timeframe_minutes
            }
        except SQLAlchemyError as e:
            error_msg = "Failed to get log statistics"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

# Create repository instances
log_source_repository = LogSourceRepository()
log_entry_repository = LogEntryRepository() 