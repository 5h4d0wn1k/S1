from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from ..models.report import (
    ReportTemplate,
    Report,
    ReportSchedule,
    ReportDelivery,
    ReportMetrics,
    ReportType,
    ReportFormat,
    ReportStatus,
    ReportScheduleFrequency
)
from .base import BaseRepository
from ..utils.logging import LoggerMixin
from ..core.exceptions import DatabaseError

class ReportTemplateRepository(BaseRepository[ReportTemplate], LoggerMixin):
    """Repository for managing report templates."""

    def __init__(self):
        """Initialize the repository with ReportTemplate model."""
        super().__init__(ReportTemplate)
        self.logger.info("Initialized ReportTemplateRepository")

    async def get_templates_by_type(
        self,
        session: AsyncSession,
        report_type: ReportType,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[ReportTemplate]:
        """Get report templates by type with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.report_type == report_type)
                .order_by(self.model.name)
                .offset(skip)
                .limit(limit)
            )
            templates = result.scalars().all()
            self.logger.debug(f"Retrieved {len(templates)} templates of type {report_type}")
            return templates
        except SQLAlchemyError as e:
            error_msg = f"Failed to get templates by type {report_type}: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

    async def get_template_with_parameters(
        self,
        session: AsyncSession,
        template_id: UUID
    ) -> Optional[ReportTemplate]:
        """Get report template with its parameters."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.id == template_id)
                .options(selectinload(self.model.parameters))
            )
            template = result.scalar_one_or_none()
            if template:
                self.logger.debug(f"Retrieved template {template_id} with {len(template.parameters)} parameters")
            else:
                self.logger.debug(f"No template found with ID {template_id}")
            return template
        except SQLAlchemyError as e:
            error_msg = f"Failed to get template with parameters for ID {template_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

class ReportRepository(BaseRepository[Report], LoggerMixin):
    """Repository for managing generated reports."""

    def __init__(self):
        """Initialize the repository with Report model."""
        super().__init__(Report)
        self.logger.info("Initialized ReportRepository")

    async def get_reports_by_template(
        self,
        session: AsyncSession,
        template_id: UUID,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Report]:
        """Get generated reports by template ID with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.template_id == template_id)
                .order_by(self.model.generated_at.desc())
                .offset(skip)
                .limit(limit)
            )
            reports = result.scalars().all()
            self.logger.debug(f"Retrieved {len(reports)} reports for template {template_id}")
            return reports
        except SQLAlchemyError as e:
            error_msg = f"Failed to get reports for template {template_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_reports_by_status(
        self,
        session: AsyncSession,
        status: ReportStatus,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[Report]:
        """Get reports by status with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.status == status)
                .order_by(self.model.generated_at.desc())
                .offset(skip)
                .limit(limit)
            )
            reports = result.scalars().all()
            self.logger.debug(f"Retrieved {len(reports)} reports with status {status}")
            return reports
        except SQLAlchemyError as e:
            error_msg = f"Failed to get reports by status {status}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_report_metrics(
        self,
        session: AsyncSession,
        template_id: Optional[UUID] = None,
        timeframe_minutes: int = 1440
    ) -> Dict[str, Any]:
        """Get report generation metrics."""
        try:
            start_time = datetime.utcnow() - timedelta(minutes=timeframe_minutes)
            
            # Base query
            query = select(
                func.count(self.model.id).label('total_count'),
                func.avg(self.model.generation_time).label('avg_generation_time'),
                func.sum(case(
                    (self.model.status == ReportStatus.ERROR, 1),
                    else_=0
                )).label('error_count')
            ).where(self.model.generated_at >= start_time)

            if template_id:
                query = query.where(self.model.template_id == template_id)

            result = await session.execute(query)
            metrics = result.first()

            # Get status distribution
            status_counts = await session.execute(
                select(
                    self.model.status,
                    func.count(self.model.id)
                )
                .where(self.model.generated_at >= start_time)
                .group_by(self.model.status)
            )

            return {
                "total_count": metrics.total_count,
                "avg_generation_time": float(metrics.avg_generation_time or 0),
                "error_count": metrics.error_count,
                "status_distribution": dict(status_counts.all()),
                "timeframe_minutes": timeframe_minutes
            }
        except SQLAlchemyError as e:
            error_msg = "Failed to get report metrics"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

class ReportScheduleRepository(BaseRepository[ReportSchedule], LoggerMixin):
    """Repository for managing report schedules."""

    def __init__(self):
        """Initialize the repository with ReportSchedule model."""
        super().__init__(ReportSchedule)
        self.logger.info("Initialized ReportScheduleRepository")

    async def get_active_schedules(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[ReportSchedule]:
        """Get active report schedules with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.is_active == True)
                .order_by(self.model.next_run_at)
                .offset(skip)
                .limit(limit)
            )
            schedules = result.scalars().all()
            self.logger.debug(f"Retrieved {len(schedules)} active schedules")
            return schedules
        except SQLAlchemyError as e:
            error_msg = "Failed to get active schedules"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_due_schedules(
        self,
        session: AsyncSession,
        reference_time: Optional[datetime] = None
    ) -> List[ReportSchedule]:
        """Get schedules that are due for execution."""
        try:
            if reference_time is None:
                reference_time = datetime.utcnow()

            result = await session.execute(
                select(self.model)
                .where(
                    and_(
                        self.model.is_active == True,
                        self.model.next_run_at <= reference_time
                    )
                )
                .order_by(self.model.next_run_at)
            )
            schedules = result.scalars().all()
            self.logger.debug(f"Retrieved {len(schedules)} due schedules")
            return schedules
        except SQLAlchemyError as e:
            error_msg = "Failed to get due schedules"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def update_next_run_time(
        self,
        session: AsyncSession,
        schedule_id: UUID,
        next_run_at: datetime
    ) -> ReportSchedule:
        """Update the next run time for a schedule."""
        try:
            schedule = await self.get(session, schedule_id)
            if not schedule:
                error_msg = f"Schedule {schedule_id} not found"
                self.logger.error(error_msg)
                raise DatabaseError(error_msg)

            schedule.next_run_at = next_run_at
            schedule.last_updated_at = datetime.utcnow()

            session.add(schedule)
            await session.commit()
            await session.refresh(schedule)

            self.logger.info(f"Updated next run time for schedule {schedule_id} to {next_run_at}")
            return schedule
        except SQLAlchemyError as e:
            error_msg = f"Failed to update next run time for schedule {schedule_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

class ReportDeliveryRepository(BaseRepository[ReportDelivery], LoggerMixin):
    """Repository for managing report deliveries."""

    def __init__(self):
        """Initialize the repository with ReportDelivery model."""
        super().__init__(ReportDelivery)
        self.logger.info("Initialized ReportDeliveryRepository")

    async def get_pending_deliveries(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[ReportDelivery]:
        """Get pending report deliveries with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.status == ReportStatus.PENDING)
                .order_by(self.model.created_at)
                .offset(skip)
                .limit(limit)
            )
            deliveries = result.scalars().all()
            self.logger.debug(f"Retrieved {len(deliveries)} pending deliveries")
            return deliveries
        except SQLAlchemyError as e:
            error_msg = "Failed to get pending deliveries"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def update_delivery_status(
        self,
        session: AsyncSession,
        delivery_id: UUID,
        status: ReportStatus,
        error_message: Optional[str] = None
    ) -> ReportDelivery:
        """Update the status of a report delivery."""
        try:
            delivery = await self.get(session, delivery_id)
            if not delivery:
                error_msg = f"Delivery {delivery_id} not found"
                self.logger.error(error_msg)
                raise DatabaseError(error_msg)

            delivery.status = status
            delivery.error_message = error_message
            delivery.updated_at = datetime.utcnow()

            session.add(delivery)
            await session.commit()
            await session.refresh(delivery)

            self.logger.info(f"Updated status of delivery {delivery_id} to {status}")
            return delivery
        except SQLAlchemyError as e:
            error_msg = f"Failed to update delivery status for {delivery_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

# Create repository instances
report_template_repository = ReportTemplateRepository()
report_repository = ReportRepository()
report_schedule_repository = ReportScheduleRepository()
report_delivery_repository = ReportDeliveryRepository() 