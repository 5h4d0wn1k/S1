from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models.compliance import ComplianceFramework, ComplianceControl, ComplianceAssessment
from ..engines.compliance.engine import compliance_engine
from ..utils.logging import LoggerMixin
from ..core.exceptions import ResourceNotFoundError, ValidationError

class ComplianceService(LoggerMixin):
    """Service for handling compliance monitoring and reporting."""
    
    async def add_framework(
        self,
        framework: ComplianceFramework,
        added_by: str
    ) -> ComplianceFramework:
        """Add compliance framework."""
        try:
            # Validate framework
            await self._validate_framework(framework)
            
            # Add framework
            framework = await compliance_engine.add_framework(framework)
            
            self.log_info(
                "Compliance framework added",
                framework_id=framework.id,
                name=framework.name,
                version=framework.version
            )
            
            return framework
            
        except Exception as e:
            self.log_error("Failed to add compliance framework", error=e)
            raise
    
    async def get_framework(
        self,
        framework_id: UUID
    ) -> ComplianceFramework:
        """Get compliance framework by ID."""
        try:
            framework = await compliance_engine.get_framework(framework_id)
            if not framework:
                raise ResourceNotFoundError("Compliance framework not found")
            return framework
            
        except ResourceNotFoundError:
            raise
        except Exception as e:
            self.log_error("Failed to get compliance framework", error=e, framework_id=framework_id)
            raise
    
    async def update_framework(
        self,
        framework_id: UUID,
        data: Dict,
        updated_by: str
    ) -> ComplianceFramework:
        """Update compliance framework."""
        try:
            # Get framework
            framework = await self.get_framework(framework_id)
            
            # Validate updated framework
            await self._validate_framework({**framework.model_dump(), **data})
            
            # Update framework
            framework = await compliance_engine.update_framework(framework_id, data)
            
            self.log_info(
                "Compliance framework updated",
                framework_id=framework_id,
                name=framework.name,
                updated_by=updated_by
            )
            
            return framework
            
        except Exception as e:
            self.log_error("Failed to update compliance framework", error=e, framework_id=framework_id)
            raise
    
    async def add_control(
        self,
        framework_id: UUID,
        control: ComplianceControl,
        added_by: str
    ) -> ComplianceControl:
        """Add compliance control to framework."""
        try:
            # Validate control
            await self._validate_control(control)
            
            # Add control
            control = await compliance_engine.add_control(framework_id, control)
            
            self.log_info(
                "Compliance control added",
                control_id=control.id,
                framework_id=framework_id,
                name=control.name
            )
            
            return control
            
        except Exception as e:
            self.log_error("Failed to add compliance control", error=e, framework_id=framework_id)
            raise
    
    async def update_control(
        self,
        control_id: UUID,
        data: Dict,
        updated_by: str
    ) -> ComplianceControl:
        """Update compliance control."""
        try:
            # Get control
            control = await compliance_engine.get_control(control_id)
            if not control:
                raise ResourceNotFoundError("Compliance control not found")
            
            # Validate updated control
            await self._validate_control({**control.model_dump(), **data})
            
            # Update control
            control = await compliance_engine.update_control(control_id, data)
            
            self.log_info(
                "Compliance control updated",
                control_id=control_id,
                name=control.name,
                updated_by=updated_by
            )
            
            return control
            
        except Exception as e:
            self.log_error("Failed to update compliance control", error=e, control_id=control_id)
            raise
    
    async def start_assessment(
        self,
        framework_id: UUID,
        parameters: Dict,
        started_by: str
    ) -> ComplianceAssessment:
        """Start compliance assessment."""
        try:
            # Get framework
            framework = await self.get_framework(framework_id)
            
            # Start assessment
            assessment = await compliance_engine.start_assessment(framework, parameters)
            
            self.log_info(
                "Compliance assessment started",
                assessment_id=assessment.id,
                framework_id=framework_id,
                started_by=started_by
            )
            
            return assessment
            
        except Exception as e:
            self.log_error(
                "Failed to start compliance assessment",
                error=e,
                framework_id=framework_id
            )
            raise
    
    async def get_assessment(
        self,
        assessment_id: UUID
    ) -> ComplianceAssessment:
        """Get compliance assessment by ID."""
        try:
            assessment = await compliance_engine.get_assessment(assessment_id)
            if not assessment:
                raise ResourceNotFoundError("Compliance assessment not found")
            return assessment
            
        except ResourceNotFoundError:
            raise
        except Exception as e:
            self.log_error("Failed to get compliance assessment", error=e, assessment_id=assessment_id)
            raise
    
    async def get_assessments(
        self,
        framework_id: Optional[UUID] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[ComplianceAssessment]:
        """Get compliance assessments with filters."""
        try:
            return await compliance_engine.get_assessments(
                framework_id=framework_id,
                start_time=start_time,
                end_time=end_time,
                skip=skip,
                limit=limit
            )
        except Exception as e:
            self.log_error("Failed to get compliance assessments", error=e)
            raise
    
    async def get_compliance_metrics(self) -> Dict:
        """Get compliance engine metrics."""
        try:
            metrics = {
                "frameworks": {
                    "total": len(await compliance_engine.get_frameworks()),
                    "by_status": await compliance_engine.get_framework_counts_by_status()
                },
                "controls": {
                    "total": len(await compliance_engine.get_controls()),
                    "by_framework": await compliance_engine.get_control_counts_by_framework(),
                    "by_status": await compliance_engine.get_control_counts_by_status()
                },
                "assessments": {
                    "total_today": await compliance_engine.get_assessment_count_today(),
                    "by_framework": await compliance_engine.get_assessment_counts_by_framework(),
                    "by_status": await compliance_engine.get_assessment_counts_by_status(),
                    "compliance_rate": await compliance_engine.get_compliance_rate()
                },
                "performance": {
                    "avg_assessment_time": await compliance_engine.get_avg_assessment_time(),
                    "success_rate": await compliance_engine.get_success_rate(),
                    "error_rate": await compliance_engine.get_error_rate()
                }
            }
            
            return metrics
            
        except Exception as e:
            self.log_error("Failed to get compliance metrics", error=e)
            raise
    
    async def _validate_framework(self, framework: Dict) -> None:
        """Validate compliance framework."""
        try:
            # Validate required fields
            required_fields = ["name", "version", "description", "controls"]
            for field in required_fields:
                if field not in framework:
                    raise ValidationError(f"Missing required field: {field}")
            
            # Validate controls
            if not framework["controls"]:
                raise ValidationError("Framework must have at least one control")
            
            # Validate framework configuration
            await compliance_engine._validate_framework_config(framework)
            
        except ValidationError:
            raise
        except Exception as e:
            self.log_error("Framework validation failed", error=e)
            raise
    
    async def _validate_control(self, control: Dict) -> None:
        """Validate compliance control."""
        try:
            # Validate required fields
            required_fields = ["name", "description", "requirements", "assessment_type"]
            for field in required_fields:
                if field not in control:
                    raise ValidationError(f"Missing required field: {field}")
            
            # Validate assessment type
            valid_types = ["automated", "manual", "hybrid"]
            if control["assessment_type"] not in valid_types:
                raise ValidationError(f"Invalid assessment type: {control['assessment_type']}")
            
            # Validate control configuration
            await compliance_engine._validate_control_config(control)
            
        except ValidationError:
            raise
        except Exception as e:
            self.log_error("Control validation failed", error=e)
            raise

# Create service instance
compliance_service = ComplianceService() 