from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models.log import LogEntry, LogSource, LogType
from ..engines.ingestion.engine import ingestion_engine
from ..utils.logging import LoggerMixin
from ..core.exceptions import ResourceNotFoundError, ValidationError

class LogIngestionService(LoggerMixin):
    """Service for handling log ingestion and processing."""
    
    async def start_ingestion(self) -> None:
        """Start log ingestion engine."""
        try:
            await ingestion_engine.start()
            self.log_info("Log ingestion engine started")
        except Exception as e:
            self.log_error("Failed to start log ingestion engine", error=e)
            raise
    
    async def stop_ingestion(self) -> None:
        """Stop log ingestion engine."""
        try:
            await ingestion_engine.stop()
            self.log_info("Log ingestion engine stopped")
        except Exception as e:
            self.log_error("Failed to stop log ingestion engine", error=e)
            raise
    
    async def add_source(
        self,
        source: LogSource,
        added_by: str
    ) -> LogSource:
        """Add new log source."""
        try:
            # Validate source configuration
            await self._validate_source_config(source)
            
            # Add source
            source = await ingestion_engine.add_source(source)
            
            self.log_info(
                "Log source added",
                source_id=source.id,
                name=source.name,
                type=source.type
            )
            
            return source
            
        except Exception as e:
            self.log_error("Failed to add log source", error=e)
            raise
    
    async def remove_source(
        self,
        source_id: UUID,
        removed_by: str
    ) -> bool:
        """Remove log source."""
        try:
            # Remove source
            removed = await ingestion_engine.remove_source(source_id)
            
            if removed:
                self.log_info(
                    "Log source removed",
                    source_id=source_id,
                    removed_by=removed_by
                )
                return True
            
            raise ResourceNotFoundError("Log source not found")
            
        except Exception as e:
            self.log_error("Failed to remove log source", error=e, source_id=source_id)
            raise
    
    async def get_source(
        self,
        source_id: UUID
    ) -> LogSource:
        """Get log source by ID."""
        try:
            source = await ingestion_engine.get_source(source_id)
            if not source:
                raise ResourceNotFoundError("Log source not found")
            return source
            
        except ResourceNotFoundError:
            raise
        except Exception as e:
            self.log_error("Failed to get log source", error=e, source_id=source_id)
            raise
    
    async def update_source(
        self,
        source_id: UUID,
        data: Dict,
        updated_by: str
    ) -> LogSource:
        """Update log source configuration."""
        try:
            # Get source
            source = await self.get_source(source_id)
            
            # Validate new configuration
            await self._validate_source_config({**source.model_dump(), **data})
            
            # Update source
            source = await ingestion_engine.update_source(source_id, data)
            
            self.log_info(
                "Log source updated",
                source_id=source_id,
                name=source.name,
                updated_by=updated_by
            )
            
            return source
            
        except Exception as e:
            self.log_error("Failed to update log source", error=e, source_id=source_id)
            raise
    
    async def get_logs(
        self,
        source_id: Optional[UUID] = None,
        log_type: Optional[LogType] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[LogEntry]:
        """Get logs with filters."""
        try:
            return await ingestion_engine.get_logs(
                source_id=source_id,
                log_type=log_type,
                start_time=start_time,
                end_time=end_time,
                skip=skip,
                limit=limit
            )
        except Exception as e:
            self.log_error("Failed to get logs", error=e)
            raise
    
    async def get_ingestion_metrics(self) -> Dict:
        """Get log ingestion metrics."""
        try:
            metrics = {
                "sources": {
                    "total": len(await ingestion_engine.get_sources()),
                    "active": len(await ingestion_engine.get_active_sources()),
                    "by_type": await ingestion_engine.get_source_counts_by_type()
                },
                "logs": {
                    "total_today": await ingestion_engine.get_log_count_today(),
                    "by_type": await ingestion_engine.get_log_counts_by_type(),
                    "by_source": await ingestion_engine.get_log_counts_by_source(),
                    "ingestion_rate": await ingestion_engine.get_ingestion_rate()
                },
                "performance": {
                    "avg_processing_time": await ingestion_engine.get_avg_processing_time(),
                    "queue_size": await ingestion_engine.get_queue_size(),
                    "error_rate": await ingestion_engine.get_error_rate()
                }
            }
            
            return metrics
            
        except Exception as e:
            self.log_error("Failed to get ingestion metrics", error=e)
            raise
    
    async def _validate_source_config(self, config: Dict) -> None:
        """Validate log source configuration."""
        try:
            # Validate required fields
            required_fields = ["name", "type", "configuration"]
            for field in required_fields:
                if field not in config:
                    raise ValidationError(f"Missing required field: {field}")
            
            # Validate source type
            valid_types = ["syslog", "file", "api", "aws", "azure", "gcp"]
            if config["type"] not in valid_types:
                raise ValidationError(f"Invalid source type: {config['type']}")
            
            # Validate configuration based on type
            await ingestion_engine._validate_source_config(config)
            
        except ValidationError:
            raise
        except Exception as e:
            self.log_error("Source configuration validation failed", error=e)
            raise

# Create service instance
log_ingestion_service = LogIngestionService() 