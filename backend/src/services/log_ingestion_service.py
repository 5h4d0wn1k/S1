from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..repositories.log_repository import log_source_repository, log_entry_repository
from ..models.log import (
    LogSource,
    LogEntry,
    LogBatch,
    LogType,
    LogLevel,
    LogSourceType,
    LogSourceStatus
)
from ..utils.logging import LoggerMixin
from ..core.exceptions import (
    DatabaseError,
    ValidationError,
    LogSourceError,
    LogProcessingError
)

class LogIngestionService(LoggerMixin):
    """Service for handling log ingestion and processing."""

    def __init__(self):
        """Initialize the log ingestion service."""
        self.logger.info("Initialized LogIngestionService")

    async def validate_source_config(
        self,
        source_type: LogSourceType,
        config: Dict[str, Any]
    ) -> None:
        """Validate log source configuration."""
        try:
            required_fields = {
                LogSourceType.FILE: ["path", "format"],
                LogSourceType.SYSLOG: ["port", "protocol"],
                LogSourceType.API: ["endpoint", "auth_type"],
                LogSourceType.KAFKA: ["brokers", "topic"],
                LogSourceType.WINLOG: ["channels", "subscription_name"]
            }

            if source_type not in required_fields:
                raise ValidationError(f"Unsupported log source type: {source_type}")

            missing_fields = [
                field for field in required_fields[source_type]
                if field not in config
            ]

            if missing_fields:
                raise ValidationError(
                    f"Missing required fields for {source_type}: {missing_fields}"
                )

            # Validate specific field formats/values
            if source_type == LogSourceType.SYSLOG:
                port = config["port"]
                if not isinstance(port, int) or port < 1 or port > 65535:
                    raise ValidationError("Invalid port number")

            elif source_type == LogSourceType.API:
                valid_auth_types = ["none", "basic", "token", "oauth2"]
                if config["auth_type"] not in valid_auth_types:
                    raise ValidationError(
                        f"Invalid auth_type. Must be one of: {valid_auth_types}"
                    )

            self.logger.debug(f"Validated configuration for {source_type} source")
        except Exception as e:
            error_msg = f"Configuration validation failed: {str(e)}"
            self.logger.error(error_msg)
            raise ValidationError(error_msg)

    async def add_log_source(
        self,
        session: AsyncSession,
        name: str,
        source_type: LogSourceType,
        config: Dict[str, Any]
    ) -> LogSource:
        """Add a new log source."""
        try:
            # Validate configuration
            await self.validate_source_config(source_type, config)

            # Create log source
            log_source = LogSource(
                name=name,
                type=source_type,
                config=config,
                status=LogSourceStatus.PENDING
            )

            log_source = await log_source_repository.create(session, log_source)
            self.logger.info(f"Created new log source: {name} ({source_type})")
            return log_source
        except Exception as e:
            error_msg = f"Failed to add log source: {str(e)}"
            self.logger.error(error_msg)
            raise LogSourceError(error_msg)

    async def update_source_status(
        self,
        session: AsyncSession,
        source_id: UUID,
        status: LogSourceStatus,
        error_message: Optional[str] = None
    ) -> LogSource:
        """Update log source status."""
        try:
            return await log_source_repository.update_source_status(
                session, source_id, status, error_message
            )
        except Exception as e:
            error_msg = f"Failed to update source status: {str(e)}"
            self.logger.error(error_msg)
            raise LogSourceError(error_msg)

    async def process_log_batch(
        self,
        session: AsyncSession,
        source_id: UUID,
        batch: LogBatch
    ) -> List[LogEntry]:
        """Process a batch of logs."""
        try:
            # Validate source exists and is active
            source = await log_source_repository.get(session, source_id)
            if not source:
                raise LogSourceError(f"Log source {source_id} not found")
            if source.status != LogSourceStatus.ACTIVE:
                raise LogSourceError(
                    f"Log source {source_id} is not active (status: {source.status})"
                )

            # Process and create log entries
            log_entries = []
            for raw_log in batch.entries:
                try:
                    log_entry = LogEntry(
                        source_id=source_id,
                        raw_data=raw_log,
                        timestamp=datetime.utcnow(),
                        parsed_data=self._parse_log(raw_log, source.type)
                    )
                    log_entries.append(log_entry)
                except Exception as e:
                    self.logger.warning(
                        f"Failed to parse log entry from source {source_id}: {str(e)}"
                    )
                    continue

            # Bulk create log entries
            if log_entries:
                created_entries = await log_entry_repository.bulk_create(
                    session, log_entries
                )
                self.logger.info(
                    f"Processed {len(created_entries)} logs from source {source_id}"
                )
                return created_entries
            return []
        except Exception as e:
            error_msg = f"Failed to process log batch: {str(e)}"
            self.logger.error(error_msg)
            raise LogProcessingError(error_msg)

    def _parse_log(
        self,
        raw_log: str,
        source_type: LogSourceType
    ) -> Dict[str, Any]:
        """Parse raw log data based on source type."""
        try:
            # Add source-specific parsing logic here
            # This is a placeholder implementation
            parsed_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "source_type": source_type.value,
                "raw_message": raw_log
            }

            # Add more parsing logic based on source type
            if source_type == LogSourceType.SYSLOG:
                # Parse syslog format
                pass
            elif source_type == LogSourceType.WINLOG:
                # Parse Windows Event Log format
                pass
            elif source_type == LogSourceType.FILE:
                # Parse file-based logs
                pass

            return parsed_data
        except Exception as e:
            error_msg = f"Failed to parse log: {str(e)}"
            self.logger.error(error_msg)
            raise LogProcessingError(error_msg)

    async def get_source_metrics(
        self,
        session: AsyncSession,
        source_id: UUID,
        timeframe_minutes: int = 60
    ) -> Dict[str, Any]:
        """Get metrics for a log source."""
        try:
            # Get log statistics
            stats = await log_entry_repository.get_log_statistics(
                session, timeframe_minutes
            )

            # Get source-specific metrics
            source = await log_source_repository.get(session, source_id)
            if not source:
                raise LogSourceError(f"Log source {source_id} not found")

            return {
                "source_id": source_id,
                "source_name": source.name,
                "source_type": source.type,
                "status": source.status,
                "error_count": source.error_count,
                "last_error": source.error_message,
                "statistics": stats
            }
        except Exception as e:
            error_msg = f"Failed to get source metrics: {str(e)}"
            self.logger.error(error_msg)
            raise LogSourceError(error_msg)

# Create service instance
log_ingestion_service = LogIngestionService() 