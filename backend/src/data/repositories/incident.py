from typing import List, Optional
from datetime import datetime, timedelta

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from .base import BaseRepository
from ..models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentCategory

class IncidentRepository(BaseRepository[Incident]):
    """Incident repository."""
    
    def __init__(self) -> None:
        """Initialize repository."""
        super().__init__(Incident)
    
    async def get_active_incidents(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Incident]:
        """Get active incidents."""
        try:
            stmt = (
                self.select()
                .where(
                    Incident.status.in_([
                        IncidentStatus.NEW,
                        IncidentStatus.INVESTIGATING,
                        IncidentStatus.CONTAINED
                    ])
                )
                .order_by(Incident.severity.desc(), Incident.detected_at.desc())
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get active incidents",
                error=e,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_incidents_by_severity(
        self,
        session: AsyncSession,
        severity: IncidentSeverity,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Incident]:
        """Get incidents by severity."""
        try:
            stmt = (
                self.select()
                .where(Incident.severity == severity)
                .order_by(Incident.detected_at.desc())
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get incidents by severity",
                error=e,
                severity=severity,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_incidents_by_status(
        self,
        session: AsyncSession,
        status: IncidentStatus,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Incident]:
        """Get incidents by status."""
        try:
            stmt = (
                self.select()
                .where(Incident.status == status)
                .order_by(Incident.detected_at.desc())
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get incidents by status",
                error=e,
                status=status,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_incidents_by_category(
        self,
        session: AsyncSession,
        category: IncidentCategory,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Incident]:
        """Get incidents by category."""
        try:
            stmt = (
                self.select()
                .where(Incident.category == category)
                .order_by(Incident.detected_at.desc())
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get incidents by category",
                error=e,
                category=category,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_incidents_by_timerange(
        self,
        session: AsyncSession,
        start_time: datetime,
        end_time: datetime,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Incident]:
        """Get incidents within time range."""
        try:
            stmt = (
                self.select()
                .where(
                    Incident.detected_at >= start_time,
                    Incident.detected_at <= end_time
                )
                .order_by(Incident.detected_at.desc())
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get incidents by timerange",
                error=e,
                start_time=start_time,
                end_time=end_time,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_incidents_by_lead(
        self,
        session: AsyncSession,
        lead_id: int,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Incident]:
        """Get incidents by lead."""
        try:
            stmt = (
                self.select()
                .where(Incident.lead_id == lead_id)
                .order_by(Incident.detected_at.desc())
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get incidents by lead",
                error=e,
                lead_id=lead_id,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_incidents_by_team_member(
        self,
        session: AsyncSession,
        user_id: int,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Incident]:
        """Get incidents by team member."""
        try:
            stmt = (
                self.select()
                .join(Incident.assigned_users)
                .where(User.id == user_id)
                .order_by(Incident.detected_at.desc())
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get incidents by team member",
                error=e,
                user_id=user_id,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_incidents_stats(
        self,
        session: AsyncSession,
        days: int = 30
    ) -> dict:
        """Get incident statistics."""
        try:
            start_time = datetime.utcnow() - timedelta(days=days)
            
            # Get total counts by severity
            severity_stmt = (
                select(Incident.severity, func.count(Incident.id))
                .where(Incident.detected_at >= start_time)
                .group_by(Incident.severity)
            )
            severity_result = await session.execute(severity_stmt)
            severity_stats = dict(severity_result.all())
            
            # Get total counts by status
            status_stmt = (
                select(Incident.status, func.count(Incident.id))
                .where(Incident.detected_at >= start_time)
                .group_by(Incident.status)
            )
            status_result = await session.execute(status_stmt)
            status_stats = dict(status_result.all())
            
            # Get total counts by category
            category_stmt = (
                select(Incident.category, func.count(Incident.id))
                .where(Incident.detected_at >= start_time)
                .group_by(Incident.category)
            )
            category_result = await session.execute(category_stmt)
            category_stats = dict(category_result.all())
            
            # Get average time to containment
            containment_stmt = (
                select(func.avg(
                    Incident.contained_at - Incident.detected_at
                ))
                .where(
                    Incident.detected_at >= start_time,
                    Incident.contained_at.isnot(None)
                )
            )
            containment_result = await session.execute(containment_stmt)
            avg_containment_time = containment_result.scalar_one_or_none()
            
            # Get average time to resolution
            resolution_stmt = (
                select(func.avg(
                    Incident.resolved_at - Incident.detected_at
                ))
                .where(
                    Incident.detected_at >= start_time,
                    Incident.resolved_at.isnot(None)
                )
            )
            resolution_result = await session.execute(resolution_stmt)
            avg_resolution_time = resolution_result.scalar_one_or_none()
            
            return {
                "severity": severity_stats,
                "status": status_stats,
                "category": category_stats,
                "total": sum(severity_stats.values()),
                "avg_containment_time": avg_containment_time,
                "avg_resolution_time": avg_resolution_time
            }
        except Exception as e:
            self.log_error(
                "Failed to get incident statistics",
                error=e,
                days=days
            )
            raise

# Create repository instance
incident_repository = IncidentRepository() 