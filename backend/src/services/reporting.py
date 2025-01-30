from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models.report import Report, ReportTemplate, ReportSchedule
from ..engines.reporting.engine import reporting_engine
from ..utils.logging import LoggerMixin
from ..core.exceptions import ResourceNotFoundError, ValidationError

class ReportingService(LoggerMixin):
    """Service for handling report generation and analytics."""
    
    async def create_template(
        self,
        template: ReportTemplate,
        created_by: str
    ) -> ReportTemplate:
        """Create report template."""
        try:
            # Validate template
            await self._validate_template(template)
            
            # Create template
            template = await reporting_engine.create_template(template)
            
            self.log_info(
                "Report template created",
                template_id=template.id,
                name=template.name,
                type=template.report_type
            )
            
            return template
            
        except Exception as e:
            self.log_error("Failed to create report template", error=e)
            raise
    
    async def get_template(
        self,
        template_id: UUID
    ) -> ReportTemplate:
        """Get report template by ID."""
        try:
            template = await reporting_engine.get_template(template_id)
            if not template:
                raise ResourceNotFoundError("Report template not found")
            return template
            
        except ResourceNotFoundError:
            raise
        except Exception as e:
            self.log_error("Failed to get report template", error=e, template_id=template_id)
            raise
    
    async def update_template(
        self,
        template_id: UUID,
        data: Dict,
        updated_by: str
    ) -> ReportTemplate:
        """Update report template."""
        try:
            # Get template
            template = await self.get_template(template_id)
            
            # Validate updated template
            await self._validate_template({**template.model_dump(), **data})
            
            # Update template
            template = await reporting_engine.update_template(template_id, data)
            
            self.log_info(
                "Report template updated",
                template_id=template_id,
                name=template.name,
                updated_by=updated_by
            )
            
            return template
            
        except Exception as e:
            self.log_error("Failed to update report template", error=e, template_id=template_id)
            raise
    
    async def delete_template(
        self,
        template_id: UUID,
        deleted_by: str
    ) -> bool:
        """Delete report template."""
        try:
            # Delete template
            deleted = await reporting_engine.delete_template(template_id)
            
            if deleted:
                self.log_info(
                    "Report template deleted",
                    template_id=template_id,
                    deleted_by=deleted_by
                )
                return True
            
            raise ResourceNotFoundError("Report template not found")
            
        except Exception as e:
            self.log_error("Failed to delete report template", error=e, template_id=template_id)
            raise
    
    async def generate_report(
        self,
        template_id: UUID,
        parameters: Dict,
        generated_by: str
    ) -> Report:
        """Generate report from template."""
        try:
            # Get template
            template = await self.get_template(template_id)
            
            # Generate report
            report = await reporting_engine.generate_report(template, parameters)
            
            self.log_info(
                "Report generated",
                report_id=report.id,
                template_id=template_id,
                generated_by=generated_by
            )
            
            return report
            
        except Exception as e:
            self.log_error(
                "Failed to generate report",
                error=e,
                template_id=template_id
            )
            raise
    
    async def schedule_report(
        self,
        template_id: UUID,
        schedule: ReportSchedule,
        scheduled_by: str
    ) -> ReportSchedule:
        """Schedule periodic report generation."""
        try:
            # Validate schedule
            await self._validate_schedule(schedule)
            
            # Schedule report
            schedule = await reporting_engine.schedule_report(template_id, schedule)
            
            self.log_info(
                "Report scheduled",
                schedule_id=schedule.id,
                template_id=template_id,
                frequency=schedule.frequency
            )
            
            return schedule
            
        except Exception as e:
            self.log_error(
                "Failed to schedule report",
                error=e,
                template_id=template_id
            )
            raise
    
    async def get_report(
        self,
        report_id: UUID
    ) -> Report:
        """Get generated report by ID."""
        try:
            report = await reporting_engine.get_report(report_id)
            if not report:
                raise ResourceNotFoundError("Report not found")
            return report
            
        except ResourceNotFoundError:
            raise
        except Exception as e:
            self.log_error("Failed to get report", error=e, report_id=report_id)
            raise
    
    async def get_reports(
        self,
        template_id: Optional[UUID] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Report]:
        """Get generated reports with filters."""
        try:
            return await reporting_engine.get_reports(
                template_id=template_id,
                start_time=start_time,
                end_time=end_time,
                skip=skip,
                limit=limit
            )
        except Exception as e:
            self.log_error("Failed to get reports", error=e)
            raise
    
    async def get_reporting_metrics(self) -> Dict:
        """Get reporting engine metrics."""
        try:
            metrics = {
                "templates": {
                    "total": len(await reporting_engine.get_templates()),
                    "by_type": await reporting_engine.get_template_counts_by_type()
                },
                "reports": {
                    "total_today": await reporting_engine.get_report_count_today(),
                    "by_template": await reporting_engine.get_report_counts_by_template(),
                    "by_status": await reporting_engine.get_report_counts_by_status()
                },
                "schedules": {
                    "active": len(await reporting_engine.get_active_schedules()),
                    "by_frequency": await reporting_engine.get_schedule_counts_by_frequency()
                },
                "performance": {
                    "avg_generation_time": await reporting_engine.get_avg_generation_time(),
                    "success_rate": await reporting_engine.get_success_rate(),
                    "error_rate": await reporting_engine.get_error_rate()
                }
            }
            
            return metrics
            
        except Exception as e:
            self.log_error("Failed to get reporting metrics", error=e)
            raise
    
    async def _validate_template(self, template: Dict) -> None:
        """Validate report template."""
        try:
            # Validate required fields
            required_fields = ["name", "report_type", "content", "parameters"]
            for field in required_fields:
                if field not in template:
                    raise ValidationError(f"Missing required field: {field}")
            
            # Validate report type
            valid_types = ["incident", "alert", "compliance", "metrics", "audit"]
            if template["report_type"] not in valid_types:
                raise ValidationError(f"Invalid report type: {template['report_type']}")
            
            # Validate template content and parameters
            await reporting_engine._validate_template_config(template)
            
        except ValidationError:
            raise
        except Exception as e:
            self.log_error("Template validation failed", error=e)
            raise
    
    async def _validate_schedule(self, schedule: ReportSchedule) -> None:
        """Validate report schedule."""
        try:
            # Validate frequency
            valid_frequencies = ["daily", "weekly", "monthly", "quarterly"]
            if schedule.frequency not in valid_frequencies:
                raise ValidationError(f"Invalid schedule frequency: {schedule.frequency}")
            
            # Validate schedule parameters
            if schedule.frequency == "weekly" and not schedule.day_of_week:
                raise ValidationError("Day of week required for weekly schedule")
            elif schedule.frequency == "monthly" and not schedule.day_of_month:
                raise ValidationError("Day of month required for monthly schedule")
            
            # Validate time
            if not schedule.time:
                raise ValidationError("Schedule time is required")
            
        except ValidationError:
            raise
        except Exception as e:
            self.log_error("Schedule validation failed", error=e)
            raise

# Create service instance
reporting_service = ReportingService() 