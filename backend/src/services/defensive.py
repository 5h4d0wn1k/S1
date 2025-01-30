from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models.alert import Alert, AlertSeverity, AlertCategory
from ..engines.defensive.engine import defensive_engine, ThreatRule, ThreatIndicator, ResponseAction
from ..utils.logging import LoggerMixin
from ..core.exceptions import ResourceNotFoundError, ValidationError

class DefensiveService(LoggerMixin):
    """Service for handling defensive security operations."""
    
    async def start_engine(self) -> None:
        """Start defensive engine."""
        try:
            await defensive_engine.start()
            self.log_info("Defensive engine started")
        except Exception as e:
            self.log_error("Failed to start defensive engine", error=e)
            raise
    
    async def stop_engine(self) -> None:
        """Stop defensive engine."""
        try:
            await defensive_engine.stop()
            self.log_info("Defensive engine stopped")
        except Exception as e:
            self.log_error("Failed to stop defensive engine", error=e)
            raise
    
    async def add_rule(
        self,
        rule: ThreatRule,
        created_by: str
    ) -> ThreatRule:
        """Add detection rule."""
        try:
            # Add rule
            rule = await defensive_engine.add_rule(rule)
            
            self.log_info(
                "Rule added",
                rule_id=rule.id,
                name=rule.name,
                type=rule.rule_type
            )
            
            return rule
            
        except Exception as e:
            self.log_error("Failed to add rule", error=e)
            raise
    
    async def add_indicator(
        self,
        indicator: ThreatIndicator,
        added_by: str
    ) -> ThreatIndicator:
        """Add threat indicator."""
        try:
            # Add indicator
            indicator = await defensive_engine.add_indicator(indicator)
            
            self.log_info(
                "Indicator added",
                type=indicator.type,
                value=indicator.value,
                source=indicator.source
            )
            
            return indicator
            
        except Exception as e:
            self.log_error("Failed to add indicator", error=e)
            raise
    
    async def block_ip(
        self,
        ip: str,
        blocked_by: str,
        reason: Optional[str] = None
    ) -> None:
        """Block IP address."""
        try:
            await defensive_engine.block_ip(ip)
            
            self.log_info(
                "IP blocked",
                ip=ip,
                blocked_by=blocked_by,
                reason=reason
            )
            
        except Exception as e:
            self.log_error("Failed to block IP", error=e, ip=ip)
            raise
    
    async def get_alerts(
        self,
        timeframe_minutes: int = 5,
        severity: Optional[AlertSeverity] = None,
        category: Optional[AlertCategory] = None
    ) -> Dict[str, List[Alert]]:
        """Get alerts from defensive engine."""
        try:
            return await defensive_engine.get_all_alerts(
                timeframe_minutes=timeframe_minutes,
                severity=severity,
                category=category
            )
            
        except Exception as e:
            self.log_error("Failed to get alerts", error=e)
            raise
    
    async def update_suricata_rules(
        self,
        rules: List[Dict]
    ) -> Dict:
        """Update Suricata rules."""
        try:
            result = await defensive_engine.update_suricata_rules(rules)
            
            self.log_info(
                "Suricata rules updated",
                added=result.get("added", 0),
                updated=result.get("updated", 0),
                removed=result.get("removed", 0)
            )
            
            return result
            
        except Exception as e:
            self.log_error("Failed to update Suricata rules", error=e)
            raise
    
    async def update_wazuh_rules(
        self,
        rules: List[Dict]
    ) -> Dict:
        """Update Wazuh rules."""
        try:
            result = await defensive_engine.update_wazuh_rules(rules)
            
            self.log_info(
                "Wazuh rules updated",
                added=result.get("added", 0),
                updated=result.get("updated", 0),
                removed=result.get("removed", 0)
            )
            
            return result
            
        except Exception as e:
            self.log_error("Failed to update Wazuh rules", error=e)
            raise
    
    async def execute_response(
        self,
        action: ResponseAction,
        executed_by: str
    ) -> None:
        """Execute automated response action."""
        try:
            # Validate action
            if action.requires_approval and not action.approved_by:
                raise ValidationError("Action requires approval")
            
            # Execute action
            await defensive_engine._execute_response(action)
            
            self.log_info(
                "Response action executed",
                action_type=action.action_type,
                executed_by=executed_by,
                parameters=action.parameters
            )
            
        except Exception as e:
            self.log_error(
                "Failed to execute response action",
                error=e,
                action_type=action.action_type
            )
            raise
    
    async def get_threat_intel(
        self,
        indicator_type: Optional[str] = None,
        value: Optional[str] = None,
        confidence_threshold: float = 0.7,
        days: int = 30
    ) -> List[ThreatIndicator]:
        """Get threat intelligence data."""
        try:
            # Get all indicators
            indicators = await defensive_engine.get_indicators(
                indicator_type=indicator_type,
                value=value,
                min_confidence=confidence_threshold,
                since=datetime.utcnow() - timedelta(days=days)
            )
            
            return indicators
            
        except Exception as e:
            self.log_error("Failed to get threat intelligence", error=e)
            raise
    
    async def get_engine_metrics(self) -> Dict:
        """Get defensive engine metrics."""
        try:
            metrics = {
                "rules": {
                    "total": len(await defensive_engine.get_rules()),
                    "enabled": len(await defensive_engine.get_rules(enabled=True)),
                    "by_type": await defensive_engine.get_rule_counts_by_type()
                },
                "indicators": {
                    "total": len(await defensive_engine.get_indicators()),
                    "by_type": await defensive_engine.get_indicator_counts_by_type(),
                    "by_confidence": await defensive_engine.get_indicator_counts_by_confidence()
                },
                "alerts": {
                    "last_24h": len(await defensive_engine.get_all_alerts(timeframe_minutes=1440)),
                    "by_severity": await defensive_engine.get_alert_counts_by_severity(),
                    "by_category": await defensive_engine.get_alert_counts_by_category()
                },
                "responses": {
                    "total_executed": await defensive_engine.get_response_count(),
                    "by_type": await defensive_engine.get_response_counts_by_type(),
                    "success_rate": await defensive_engine.get_response_success_rate()
                }
            }
            
            return metrics
            
        except Exception as e:
            self.log_error("Failed to get engine metrics", error=e)
            raise
    
    async def validate_rule(
        self,
        rule: ThreatRule
    ) -> None:
        """Validate detection rule."""
        try:
            await defensive_engine._validate_rule(rule)
        except Exception as e:
            self.log_error("Rule validation failed", error=e)
            raise
    
    async def deploy_rule(
        self,
        rule: ThreatRule,
        deployed_by: str
    ) -> None:
        """Deploy detection rule."""
        try:
            # Validate rule first
            await self.validate_rule(rule)
            
            # Deploy rule
            await defensive_engine._deploy_rule(rule)
            
            self.log_info(
                "Rule deployed",
                rule_id=rule.id,
                name=rule.name,
                type=rule.rule_type,
                deployed_by=deployed_by
            )
            
        except Exception as e:
            self.log_error("Failed to deploy rule", error=e)
            raise

# Create service instance
defensive_service = DefensiveService() 