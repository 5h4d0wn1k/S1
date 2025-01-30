from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from ..models.alert import (
    Alert,
    AlertSeverity,
    AlertCategory
)
from .base import BaseRepository
from ..utils.logging import LoggerMixin
from ..core.exceptions import DatabaseError

class AlertRepository(BaseRepository[Alert], LoggerMixin):
    """Repository for managing alerts."""

    def __init__(self):
        """Initialize the repository with Alert model."""
        super().__init__(Alert)
        self.logger.info("Initialized AlertRepository")

    async def get_active_alerts(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Alert]:
        """Get active alerts with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.status == "active")
                .order_by(self.model.timestamp.desc())
                .offset(skip)
                .limit(limit)
            )
            alerts = result.scalars().all()
            self.logger.debug(f"Retrieved {len(alerts)} active alerts")
            return alerts
        except SQLAlchemyError as e:
            error_msg = f"Failed to get active alerts: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

    async def get_alerts_by_severity(
        self,
        session: AsyncSession,
        severity: AlertSeverity,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Alert]:
        """Get alerts by severity with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.severity == severity)
                .order_by(self.model.timestamp.desc())
                .offset(skip)
                .limit(limit)
            )
            alerts = result.scalars().all()
            self.logger.debug(f"Retrieved {len(alerts)} alerts with severity {severity}")
            return alerts
        except SQLAlchemyError as e:
            error_msg = f"Failed to get alerts by severity {severity}: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

    async def get_alerts_by_category(
        self,
        session: AsyncSession,
        category: AlertCategory,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Alert]:
        """Get alerts by category with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.category == category)
                .order_by(self.model.timestamp.desc())
                .offset(skip)
                .limit(limit)
            )
            alerts = result.scalars().all()
            self.logger.debug(f"Retrieved {len(alerts)} alerts in category {category}")
            return alerts
        except SQLAlchemyError as e:
            error_msg = f"Failed to get alerts by category {category}: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

    async def get_alerts_by_criteria(
        self,
        session: AsyncSession,
        *,
        severities: Optional[List[AlertSeverity]] = None,
        categories: Optional[List[AlertCategory]] = None,
        sources: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        mitre_tactics: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Alert]:
        """Get alerts by multiple criteria with pagination."""
        try:
            conditions = []

            if severities:
                conditions.append(self.model.severity.in_(severities))
            if categories:
                conditions.append(self.model.category.in_(categories))
            if sources:
                conditions.append(self.model.source.in_(sources))
            if start_time:
                conditions.append(self.model.timestamp >= start_time)
            if end_time:
                conditions.append(self.model.timestamp <= end_time)
            if source_ip:
                conditions.append(self.model.source_ip == source_ip)
            if destination_ip:
                conditions.append(self.model.destination_ip == destination_ip)
            if mitre_tactics:
                conditions.append(self.model.mitre_tactics.overlap(mitre_tactics))
            if mitre_techniques:
                conditions.append(self.model.mitre_techniques.overlap(mitre_techniques))

            query = select(self.model)
            if conditions:
                query = query.where(and_(*conditions))

            result = await session.execute(
                query
                .order_by(self.model.timestamp.desc())
                .offset(skip)
                .limit(limit)
            )
            alerts = result.scalars().all()
            self.logger.debug(f"Retrieved {len(alerts)} alerts matching criteria")
            return alerts
        except SQLAlchemyError as e:
            error_msg = "Failed to get alerts by criteria"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_alert_statistics(
        self,
        session: AsyncSession,
        timeframe_minutes: int = 60
    ) -> Dict[str, Any]:
        """Get alert statistics for the specified timeframe."""
        try:
            start_time = datetime.utcnow() - timedelta(minutes=timeframe_minutes)
            
            # Get counts by severity
            severity_counts = await session.execute(
                select(
                    self.model.severity,
                    func.count(self.model.id)
                )
                .where(self.model.timestamp >= start_time)
                .group_by(self.model.severity)
            )
            
            # Get counts by category
            category_counts = await session.execute(
                select(
                    self.model.category,
                    func.count(self.model.id)
                )
                .where(self.model.timestamp >= start_time)
                .group_by(self.model.category)
            )
            
            # Get counts by source
            source_counts = await session.execute(
                select(
                    self.model.source,
                    func.count(self.model.id)
                )
                .where(self.model.timestamp >= start_time)
                .group_by(self.model.source)
            )

            # Get MITRE ATT&CK statistics
            mitre_stats = await session.execute(
                select(
                    func.unnest(self.model.mitre_tactics).label('tactic'),
                    func.count(self.model.id)
                )
                .where(self.model.timestamp >= start_time)
                .group_by('tactic')
            )

            return {
                "severity_counts": dict(severity_counts.all()),
                "category_counts": dict(category_counts.all()),
                "source_counts": dict(source_counts.all()),
                "mitre_tactics": dict(mitre_stats.all()),
                "timeframe_minutes": timeframe_minutes
            }
        except SQLAlchemyError as e:
            error_msg = "Failed to get alert statistics"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def update_alert_status(
        self,
        session: AsyncSession,
        alert_id: UUID,
        status: str,
        updated_by: str,
        notes: Optional[str] = None
    ) -> Alert:
        """Update alert status and add notes."""
        try:
            alert = await self.get(session, alert_id)
            if not alert:
                error_msg = f"Alert {alert_id} not found"
                self.logger.error(error_msg)
                raise DatabaseError(error_msg)

            alert.status = status
            alert.updated_by = updated_by
            if notes:
                if not alert.notes:
                    alert.notes = []
                alert.notes.append({
                    "timestamp": datetime.utcnow(),
                    "user": updated_by,
                    "note": notes
                })

            session.add(alert)
            await session.commit()
            await session.refresh(alert)

            self.logger.info(f"Updated status of alert {alert_id} to {status}")
            return alert
        except SQLAlchemyError as e:
            error_msg = f"Failed to update alert status: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

    async def bulk_update_alerts(
        self,
        session: AsyncSession,
        alert_ids: List[UUID],
        update_data: Dict[str, Any],
        updated_by: str
    ) -> List[Alert]:
        """Bulk update multiple alerts."""
        try:
            updated_alerts = []
            for alert_id in alert_ids:
                alert = await self.get(session, alert_id)
                if alert:
                    for key, value in update_data.items():
                        setattr(alert, key, value)
                    alert.updated_by = updated_by
                    session.add(alert)
                    updated_alerts.append(alert)

            await session.commit()
            for alert in updated_alerts:
                await session.refresh(alert)

            self.logger.info(f"Bulk updated {len(updated_alerts)} alerts")
            return updated_alerts
        except SQLAlchemyError as e:
            error_msg = "Failed to bulk update alerts"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

# Create repository instance
alert_repository = AlertRepository() 