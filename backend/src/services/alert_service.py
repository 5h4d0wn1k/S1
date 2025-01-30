from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..repositories.alert_repository import alert_repository
from ..repositories.correlation_repository import correlation_event_repository
from ..models.alert import (
    Alert,
    AlertSeverity,
    AlertCategory,
    AlertStatus
)
from ..models.correlation import CorrelationEvent
from ..utils.logging import LoggerMixin
from ..core.exceptions import (
    DatabaseError,
    ValidationError,
    AlertError,
    AlertProcessingError
)

class AlertService(LoggerMixin):
    """Service for managing alert generation and processing."""

    def __init__(self):
        """Initialize the alert service."""
        self.logger.info("Initialized AlertService")

    async def create_alert_from_event(
        self,
        session: AsyncSession,
        correlation_event: CorrelationEvent
    ) -> Alert:
        """Create an alert from a correlation event."""
        try:
            # Map correlation event to alert
            alert = Alert(
                title=f"Alert from {correlation_event.rule.name}",
                description=self._generate_description(correlation_event),
                severity=self._map_severity(correlation_event.severity),
                category=self._determine_category(correlation_event),
                source="correlation_engine",
                source_event_id=correlation_event.id,
                status=AlertStatus.NEW,
                timestamp=datetime.utcnow(),
                mitre_tactics=correlation_event.mitre_tactics,
                mitre_techniques=correlation_event.mitre_techniques,
                affected_assets=self._extract_affected_assets(correlation_event),
                indicators=self._extract_indicators(correlation_event)
            )

            alert = await alert_repository.create(session, alert)
            self.logger.info(
                f"Created alert {alert.id} from correlation event {correlation_event.id}"
            )
            return alert
        except Exception as e:
            error_msg = f"Failed to create alert from event: {str(e)}"
            self.logger.error(error_msg)
            raise AlertError(error_msg)

    def _generate_description(
        self,
        event: CorrelationEvent
    ) -> str:
        """Generate alert description from correlation event."""
        try:
            description = [
                f"Alert generated from correlation rule: {event.rule.name}",
                f"Severity: {event.severity.value}",
                f"Detected at: {event.timestamp.isoformat()}",
                "\nDetails:",
                f"- Rule type: {event.rule.rule_type.value}",
                f"- Confidence: {event.confidence:.2f}",
                "\nSource Events:"
            ]

            for source_event in event.source_events:
                description.append(
                    f"- {source_event.get('timestamp')}: {source_event.get('message')}"
                )

            if event.mitre_tactics:
                description.append("\nMITRE ATT&CK Tactics:")
                for tactic in event.mitre_tactics:
                    description.append(f"- {tactic}")

            if event.mitre_techniques:
                description.append("\nMITRE ATT&CK Techniques:")
                for technique in event.mitre_techniques:
                    description.append(f"- {technique}")

            return "\n".join(description)
        except Exception as e:
            self.logger.warning(f"Description generation failed: {str(e)}")
            return "Alert description generation failed"

    def _map_severity(
        self,
        correlation_severity: Any
    ) -> AlertSeverity:
        """Map correlation severity to alert severity."""
        try:
            # Implement severity mapping logic
            severity_mapping = {
                "critical": AlertSeverity.CRITICAL,
                "high": AlertSeverity.HIGH,
                "medium": AlertSeverity.MEDIUM,
                "low": AlertSeverity.LOW,
                "info": AlertSeverity.INFO
            }
            return severity_mapping.get(
                correlation_severity.value.lower(),
                AlertSeverity.MEDIUM
            )
        except Exception as e:
            self.logger.warning(f"Severity mapping failed: {str(e)}")
            return AlertSeverity.MEDIUM

    def _determine_category(
        self,
        event: CorrelationEvent
    ) -> AlertCategory:
        """Determine alert category from correlation event."""
        try:
            # Implement category determination logic based on:
            # - Rule type
            # - MITRE tactics
            # - Event patterns
            # This is a simplified implementation
            if "malware" in event.mitre_tactics:
                return AlertCategory.MALWARE
            elif "initial_access" in event.mitre_tactics:
                return AlertCategory.INTRUSION
            elif "credential_access" in event.mitre_tactics:
                return AlertCategory.CREDENTIAL_ATTACK
            elif "impact" in event.mitre_tactics:
                return AlertCategory.IMPACT
            else:
                return AlertCategory.SUSPICIOUS_ACTIVITY
        except Exception as e:
            self.logger.warning(f"Category determination failed: {str(e)}")
            return AlertCategory.SUSPICIOUS_ACTIVITY

    def _extract_affected_assets(
        self,
        event: CorrelationEvent
    ) -> List[Dict[str, Any]]:
        """Extract affected assets from correlation event."""
        try:
            assets = []
            for source_event in event.source_events:
                if "host" in source_event:
                    assets.append({
                        "type": "host",
                        "id": source_event["host"],
                        "ip": source_event.get("ip_address"),
                        "hostname": source_event.get("hostname")
                    })
                if "user" in source_event:
                    assets.append({
                        "type": "user",
                        "id": source_event["user"],
                        "domain": source_event.get("domain")
                    })
            return assets
        except Exception as e:
            self.logger.warning(f"Asset extraction failed: {str(e)}")
            return []

    def _extract_indicators(
        self,
        event: CorrelationEvent
    ) -> List[Dict[str, Any]]:
        """Extract indicators from correlation event."""
        try:
            indicators = []
            for source_event in event.source_events:
                if "ip_address" in source_event:
                    indicators.append({
                        "type": "ip",
                        "value": source_event["ip_address"]
                    })
                if "hash" in source_event:
                    indicators.append({
                        "type": "hash",
                        "value": source_event["hash"]
                    })
                if "url" in source_event:
                    indicators.append({
                        "type": "url",
                        "value": source_event["url"]
                    })
            return indicators
        except Exception as e:
            self.logger.warning(f"Indicator extraction failed: {str(e)}")
            return []

    async def process_correlation_events(
        self,
        session: AsyncSession,
        start_time: Optional[datetime] = None
    ) -> List[Alert]:
        """Process correlation events and generate alerts."""
        try:
            if start_time is None:
                start_time = datetime.utcnow() - timedelta(minutes=5)

            # Get unprocessed correlation events
            events = await correlation_event_repository.get_unprocessed_events(
                session,
                start_time
            )

            alerts = []
            for event in events:
                try:
                    alert = await self.create_alert_from_event(session, event)
                    alerts.append(alert)
                    
                    # Mark event as processed
                    event.processed = True
                    event.alert_id = alert.id
                    await correlation_event_repository.update(session, event)
                except Exception as e:
                    self.logger.warning(
                        f"Failed to process event {event.id}: {str(e)}"
                    )
                    continue

            self.logger.info(f"Generated {len(alerts)} alerts from correlation events")
            return alerts
        except Exception as e:
            error_msg = f"Failed to process correlation events: {str(e)}"
            self.logger.error(error_msg)
            raise AlertProcessingError(error_msg)

    async def update_alert_status(
        self,
        session: AsyncSession,
        alert_id: UUID,
        status: AlertStatus,
        updated_by: str,
        notes: Optional[str] = None
    ) -> Alert:
        """Update alert status and add notes."""
        try:
            return await alert_repository.update_alert_status(
                session,
                alert_id,
                status,
                updated_by,
                notes
            )
        except Exception as e:
            error_msg = f"Failed to update alert status: {str(e)}"
            self.logger.error(error_msg)
            raise AlertError(error_msg)

    async def bulk_update_alerts(
        self,
        session: AsyncSession,
        alert_ids: List[UUID],
        update_data: Dict[str, Any],
        updated_by: str
    ) -> List[Alert]:
        """Bulk update multiple alerts."""
        try:
            return await alert_repository.bulk_update_alerts(
                session,
                alert_ids,
                update_data,
                updated_by
            )
        except Exception as e:
            error_msg = f"Failed to bulk update alerts: {str(e)}"
            self.logger.error(error_msg)
            raise AlertError(error_msg)

    async def get_alert_metrics(
        self,
        session: AsyncSession,
        timeframe_minutes: int = 60
    ) -> Dict[str, Any]:
        """Get alert metrics and statistics."""
        try:
            return await alert_repository.get_alert_statistics(
                session,
                timeframe_minutes
            )
        except Exception as e:
            error_msg = f"Failed to get alert metrics: {str(e)}"
            self.logger.error(error_msg)
            raise AlertError(error_msg)

# Create service instance
alert_service = AlertService() 