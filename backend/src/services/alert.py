from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models.alert import Alert, AlertSeverity, AlertCategory
from ..data.repositories.alert import alert_repository
from ..utils.logging import LoggerMixin
from ..core.exceptions import ResourceNotFoundError
from .ai import ai_service

class AlertService(LoggerMixin):
    """Service for handling alert-related operations."""
    
    async def create_alert(
        self,
        session: AsyncSession,
        data: Dict,
        created_by: str
    ) -> Alert:
        """Create new alert."""
        try:
            # Set initial values
            data["status"] = "new"
            data["created_at"] = datetime.utcnow()
            data["updated_at"] = datetime.utcnow()
            
            # Create alert
            alert = await alert_repository.create(session, data)
            
            # Enrich alert with AI analysis
            try:
                analysis = await ai_service.analyze_alert(alert)
                alert = await alert_repository.update(
                    session,
                    db_obj=alert,
                    obj_in={"ai_analysis": analysis}
                )
            except Exception as e:
                self.log_error("Failed to analyze alert with AI", error=e)
            
            await session.commit()
            
            self.log_info(
                "Alert created",
                alert_id=alert.id,
                title=alert.title,
                severity=alert.severity,
                source=alert.source
            )
            
            return alert
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to create alert", error=e)
            raise
    
    async def get_alert(
        self,
        session: AsyncSession,
        uuid: UUID
    ) -> Alert:
        """Get alert by UUID."""
        try:
            alert = await alert_repository.get_by_uuid(session, uuid)
            if not alert:
                raise ResourceNotFoundError("Alert not found")
            return alert
            
        except ResourceNotFoundError:
            raise
        except Exception as e:
            self.log_error("Failed to get alert", error=e, uuid=uuid)
            raise
    
    async def update_alert(
        self,
        session: AsyncSession,
        uuid: UUID,
        data: Dict,
        updated_by: str
    ) -> Alert:
        """Update alert."""
        try:
            # Get alert
            alert = await self.get_alert(session, uuid)
            
            # Update alert
            data["updated_at"] = datetime.utcnow()
            alert = await alert_repository.update(
                session,
                db_obj=alert,
                obj_in=data
            )
            
            await session.commit()
            
            self.log_info(
                "Alert updated",
                alert_id=alert.id,
                title=alert.title,
                status=alert.status
            )
            
            return alert
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to update alert", error=e, uuid=uuid)
            raise
    
    async def delete_alert(
        self,
        session: AsyncSession,
        uuid: UUID,
        deleted_by: str
    ) -> bool:
        """Delete alert."""
        try:
            # Get alert
            alert = await self.get_alert(session, uuid)
            
            # Delete alert
            deleted = await alert_repository.delete(session, id=alert.id)
            
            await session.commit()
            
            if deleted:
                self.log_info(
                    "Alert deleted",
                    alert_id=uuid,
                    deleted_by=deleted_by
                )
                return True
            
            raise ResourceNotFoundError("Alert not found")
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to delete alert", error=e, uuid=uuid)
            raise
    
    async def assign_alert(
        self,
        session: AsyncSession,
        uuid: UUID,
        user_id: int,
        assigned_by: str
    ) -> Alert:
        """Assign alert to user."""
        try:
            # Get alert
            alert = await self.get_alert(session, uuid)
            
            # Update alert
            alert = await alert_repository.update(
                session,
                db_obj=alert,
                obj_in={
                    "assigned_to": user_id,
                    "updated_at": datetime.utcnow()
                }
            )
            
            await session.commit()
            
            self.log_info(
                "Alert assigned",
                alert_id=alert.id,
                title=alert.title,
                assigned_to=user_id
            )
            
            return alert
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to assign alert", error=e, uuid=uuid)
            raise
    
    async def resolve_alert(
        self,
        session: AsyncSession,
        uuid: UUID,
        notes: Optional[str],
        resolved_by: str
    ) -> Alert:
        """Resolve alert."""
        try:
            # Get alert
            alert = await self.get_alert(session, uuid)
            
            # Update alert
            alert = await alert_repository.update(
                session,
                db_obj=alert,
                obj_in={
                    "status": "resolved",
                    "resolved_by": resolved_by,
                    "resolution_notes": notes,
                    "resolved_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
            )
            
            await session.commit()
            
            self.log_info(
                "Alert resolved",
                alert_id=alert.id,
                title=alert.title,
                resolved_by=resolved_by
            )
            
            return alert
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to resolve alert", error=e, uuid=uuid)
            raise
    
    async def mark_false_positive(
        self,
        session: AsyncSession,
        uuid: UUID,
        reason: str,
        marked_by: str
    ) -> Alert:
        """Mark alert as false positive."""
        try:
            # Get alert
            alert = await self.get_alert(session, uuid)
            
            # Update alert
            alert = await alert_repository.update(
                session,
                db_obj=alert,
                obj_in={
                    "status": "false_positive",
                    "false_positive_reason": reason,
                    "resolved_by": marked_by,
                    "resolved_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
            )
            
            await session.commit()
            
            self.log_info(
                "Alert marked as false positive",
                alert_id=alert.id,
                title=alert.title,
                marked_by=marked_by
            )
            
            return alert
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to mark alert as false positive", error=e, uuid=uuid)
            raise
    
    async def get_alerts(
        self,
        session: AsyncSession,
        *,
        severity: Optional[AlertSeverity] = None,
        status: Optional[str] = None,
        source: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Alert]:
        """Get alerts with filters."""
        try:
            return await alert_repository.get_alerts(
                session,
                severity=severity,
                status=status,
                source=source,
                start_time=start_time,
                end_time=end_time,
                skip=skip,
                limit=limit
            )
        except Exception as e:
            self.log_error("Failed to get alerts", error=e)
            raise
    
    async def get_active_alerts(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Alert]:
        """Get active alerts."""
        try:
            return await alert_repository.get_active_alerts(
                session,
                skip=skip,
                limit=limit
            )
        except Exception as e:
            self.log_error("Failed to get active alerts", error=e)
            raise
    
    async def get_alert_stats(
        self,
        session: AsyncSession,
        days: int = 7
    ) -> dict:
        """Get alert statistics."""
        try:
            return await alert_repository.get_alert_stats(session, days=days)
        except Exception as e:
            self.log_error("Failed to get alert statistics", error=e)
            raise
    
    async def bulk_update_alerts(
        self,
        session: AsyncSession,
        alert_ids: List[UUID],
        data: Dict,
        updated_by: str
    ) -> List[Alert]:
        """Update multiple alerts."""
        try:
            updated_alerts = []
            failed_ids = []
            
            for alert_id in alert_ids:
                try:
                    alert = await self.update_alert(
                        session,
                        alert_id,
                        data,
                        updated_by
                    )
                    updated_alerts.append(alert)
                except Exception as e:
                    failed_ids.append(alert_id)
                    self.log_error(
                        "Failed to update alert in bulk operation",
                        error=e,
                        alert_id=alert_id
                    )
            
            if failed_ids:
                self.log_warning(
                    "Some alerts failed to update in bulk operation",
                    failed_ids=failed_ids
                )
            
            return updated_alerts
            
        except Exception as e:
            await session.rollback()
            self.log_error("Failed to perform bulk alert update", error=e)
            raise

# Create service instance
alert_service = AlertService() 