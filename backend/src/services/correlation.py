from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models.alert import Alert
from ..data.models.incident import Incident
from ..data.models.correlation import CorrelationRule, CorrelationEvent
from ..engines.correlation.engine import correlation_engine
from ..utils.logging import LoggerMixin
from ..core.exceptions import ResourceNotFoundError, ValidationError

class CorrelationService(LoggerMixin):
    """Service for handling event correlation and analysis."""
    
    async def start_correlation(self) -> None:
        """Start correlation engine."""
        try:
            await correlation_engine.start()
            self.log_info("Correlation engine started")
        except Exception as e:
            self.log_error("Failed to start correlation engine", error=e)
            raise
    
    async def stop_correlation(self) -> None:
        """Stop correlation engine."""
        try:
            await correlation_engine.stop()
            self.log_info("Correlation engine stopped")
        except Exception as e:
            self.log_error("Failed to stop correlation engine", error=e)
            raise
    
    async def add_rule(
        self,
        rule: CorrelationRule,
        created_by: str
    ) -> CorrelationRule:
        """Add correlation rule."""
        try:
            # Validate rule
            await self._validate_rule(rule)
            
            # Add rule
            rule = await correlation_engine.add_rule(rule)
            
            self.log_info(
                "Correlation rule added",
                rule_id=rule.id,
                name=rule.name,
                type=rule.rule_type
            )
            
            return rule
            
        except Exception as e:
            self.log_error("Failed to add correlation rule", error=e)
            raise
    
    async def remove_rule(
        self,
        rule_id: UUID,
        removed_by: str
    ) -> bool:
        """Remove correlation rule."""
        try:
            # Remove rule
            removed = await correlation_engine.remove_rule(rule_id)
            
            if removed:
                self.log_info(
                    "Correlation rule removed",
                    rule_id=rule_id,
                    removed_by=removed_by
                )
                return True
            
            raise ResourceNotFoundError("Correlation rule not found")
            
        except Exception as e:
            self.log_error("Failed to remove correlation rule", error=e, rule_id=rule_id)
            raise
    
    async def get_rule(
        self,
        rule_id: UUID
    ) -> CorrelationRule:
        """Get correlation rule by ID."""
        try:
            rule = await correlation_engine.get_rule(rule_id)
            if not rule:
                raise ResourceNotFoundError("Correlation rule not found")
            return rule
            
        except ResourceNotFoundError:
            raise
        except Exception as e:
            self.log_error("Failed to get correlation rule", error=e, rule_id=rule_id)
            raise
    
    async def update_rule(
        self,
        rule_id: UUID,
        data: Dict,
        updated_by: str
    ) -> CorrelationRule:
        """Update correlation rule."""
        try:
            # Get rule
            rule = await self.get_rule(rule_id)
            
            # Validate updated rule
            await self._validate_rule({**rule.model_dump(), **data})
            
            # Update rule
            rule = await correlation_engine.update_rule(rule_id, data)
            
            self.log_info(
                "Correlation rule updated",
                rule_id=rule_id,
                name=rule.name,
                updated_by=updated_by
            )
            
            return rule
            
        except Exception as e:
            self.log_error("Failed to update correlation rule", error=e, rule_id=rule_id)
            raise
    
    async def get_correlated_events(
        self,
        rule_id: Optional[UUID] = None,
        severity: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[CorrelationEvent]:
        """Get correlated events with filters."""
        try:
            return await correlation_engine.get_events(
                rule_id=rule_id,
                severity=severity,
                start_time=start_time,
                end_time=end_time,
                skip=skip,
                limit=limit
            )
        except Exception as e:
            self.log_error("Failed to get correlated events", error=e)
            raise
    
    async def analyze_event_chain(
        self,
        event_id: UUID
    ) -> Dict:
        """Analyze event correlation chain."""
        try:
            # Get event chain
            chain = await correlation_engine.get_event_chain(event_id)
            
            # Analyze chain
            analysis = await correlation_engine.analyze_chain(chain)
            
            return {
                "event_id": event_id,
                "chain_length": len(chain),
                "root_cause": analysis.get("root_cause"),
                "impact": analysis.get("impact"),
                "recommendations": analysis.get("recommendations", []),
                "chain": chain
            }
            
        except Exception as e:
            self.log_error("Failed to analyze event chain", error=e, event_id=event_id)
            raise
    
    async def correlate_events(
        self,
        events: List[Dict],
        timeframe_minutes: int = 60
    ) -> List[CorrelationEvent]:
        """Correlate events using active rules."""
        try:
            # Get active rules
            rules = await correlation_engine.get_active_rules()
            
            # Correlate events
            correlated_events = await correlation_engine.correlate(
                events,
                rules,
                timeframe_minutes=timeframe_minutes
            )
            
            self.log_info(
                "Events correlated",
                event_count=len(events),
                correlation_count=len(correlated_events)
            )
            
            return correlated_events
            
        except Exception as e:
            self.log_error(
                "Failed to correlate events",
                error=e,
                event_count=len(events)
            )
            raise
    
    async def analyze_alert_chain(
        self,
        alert: Alert,
        depth: int = 3,
        timeframe_minutes: int = 60
    ) -> Dict:
        """Analyze alert chain for potential incident."""
        try:
            # Get related alerts
            related_alerts = await correlation_engine.find_related_alerts(
                alert,
                depth=depth,
                timeframe_minutes=timeframe_minutes
            )
            
            # Analyze chain
            chain_analysis = await correlation_engine.analyze_chain(
                alert,
                related_alerts
            )
            
            self.log_info(
                "Alert chain analyzed",
                alert_id=alert.id,
                related_count=len(related_alerts)
            )
            
            return chain_analysis
            
        except Exception as e:
            self.log_error(
                "Failed to analyze alert chain",
                error=e,
                alert_id=alert.id
            )
            raise
    
    async def detect_campaign(
        self,
        alerts: List[Alert],
        timeframe_minutes: int = 1440
    ) -> Optional[Dict]:
        """Detect potential attack campaign from alerts."""
        try:
            # Analyze alerts for campaign patterns
            campaign = await correlation_engine.detect_campaign(
                alerts,
                timeframe_minutes=timeframe_minutes
            )
            
            if campaign:
                self.log_info(
                    "Campaign detected",
                    campaign_id=campaign["id"],
                    alert_count=len(alerts)
                )
            
            return campaign
            
        except Exception as e:
            self.log_error(
                "Failed to detect campaign",
                error=e,
                alert_count=len(alerts)
            )
            raise
    
    async def get_correlation_metrics(self) -> Dict:
        """Get correlation engine metrics."""
        try:
            metrics = {
                "rules": {
                    "total": len(await correlation_engine.get_rules()),
                    "active": len(await correlation_engine.get_active_rules()),
                    "by_type": await correlation_engine.get_rule_counts_by_type()
                },
                "events": {
                    "total_today": await correlation_engine.get_event_count_today(),
                    "by_severity": await correlation_engine.get_event_counts_by_severity(),
                    "by_rule": await correlation_engine.get_event_counts_by_rule(),
                    "correlation_rate": await correlation_engine.get_correlation_rate()
                },
                "performance": {
                    "avg_processing_time": await correlation_engine.get_avg_processing_time(),
                    "queue_size": await correlation_engine.get_queue_size(),
                    "error_rate": await correlation_engine.get_error_rate()
                }
            }
            
            return metrics
            
        except Exception as e:
            self.log_error("Failed to get correlation metrics", error=e)
            raise
    
    async def _validate_rule(self, rule: Dict) -> None:
        """Validate correlation rule."""
        try:
            # Validate required fields
            required_fields = ["name", "rule_type", "conditions", "actions"]
            for field in required_fields:
                if field not in rule:
                    raise ValidationError(f"Missing required field: {field}")
            
            # Validate rule type
            valid_types = ["sequence", "threshold", "pattern", "anomaly"]
            if rule["rule_type"] not in valid_types:
                raise ValidationError(f"Invalid rule type: {rule['rule_type']}")
            
            # Validate conditions and actions
            await correlation_engine._validate_rule_logic(rule)
            
        except ValidationError:
            raise
        except Exception as e:
            self.log_error("Rule validation failed", error=e)
            raise

# Create service instance
correlation_service = CorrelationService() 