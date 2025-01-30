from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Set
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..repositories.correlation_repository import (
    correlation_rule_repository,
    correlation_event_repository,
    event_chain_repository
)
from ..models.correlation import (
    CorrelationRule,
    CorrelationEvent,
    EventChain,
    CorrelationRuleType,
    CorrelationRuleStatus,
    CorrelationSeverity
)
from ..utils.logging import LoggerMixin
from ..core.exceptions import (
    DatabaseError,
    ValidationError,
    CorrelationError,
    EventProcessingError
)

class CorrelationService(LoggerMixin):
    """Service for managing event correlation and analysis."""

    def __init__(self):
        """Initialize the correlation service."""
        self.logger.info("Initialized CorrelationService")

    async def validate_rule_config(
        self,
        rule_type: CorrelationRuleType,
        config: Dict[str, Any]
    ) -> None:
        """Validate correlation rule configuration."""
        try:
            required_fields = {
                CorrelationRuleType.THRESHOLD: ["threshold", "timeframe"],
                CorrelationRuleType.SEQUENCE: ["events", "max_gap"],
                CorrelationRuleType.PATTERN: ["pattern", "conditions"],
                CorrelationRuleType.AGGREGATION: ["group_by", "metrics"],
                CorrelationRuleType.ANOMALY: ["baseline", "sensitivity"]
            }

            if rule_type not in required_fields:
                raise ValidationError(f"Unsupported rule type: {rule_type}")

            missing_fields = [
                field for field in required_fields[rule_type]
                if field not in config
            ]

            if missing_fields:
                raise ValidationError(
                    f"Missing required fields for {rule_type}: {missing_fields}"
                )

            # Validate specific field formats/values
            if rule_type == CorrelationRuleType.THRESHOLD:
                threshold = config["threshold"]
                timeframe = config["timeframe"]
                if not isinstance(threshold, int) or threshold < 1:
                    raise ValidationError("Invalid threshold value")
                if not isinstance(timeframe, int) or timeframe < 1:
                    raise ValidationError("Invalid timeframe value")

            elif rule_type == CorrelationRuleType.SEQUENCE:
                events = config["events"]
                if not isinstance(events, list) or len(events) < 2:
                    raise ValidationError("Sequence must contain at least 2 events")

            self.logger.debug(f"Validated configuration for {rule_type} rule")
        except Exception as e:
            error_msg = f"Rule configuration validation failed: {str(e)}"
            self.logger.error(error_msg)
            raise ValidationError(error_msg)

    async def add_correlation_rule(
        self,
        session: AsyncSession,
        name: str,
        rule_type: CorrelationRuleType,
        config: Dict[str, Any],
        severity: CorrelationSeverity
    ) -> CorrelationRule:
        """Add a new correlation rule."""
        try:
            # Validate configuration
            await self.validate_rule_config(rule_type, config)

            # Create correlation rule
            rule = CorrelationRule(
                name=name,
                rule_type=rule_type,
                config=config,
                severity=severity,
                status=CorrelationRuleStatus.ACTIVE
            )

            rule = await correlation_rule_repository.create(session, rule)
            self.logger.info(f"Created new correlation rule: {name} ({rule_type})")
            return rule
        except Exception as e:
            error_msg = f"Failed to add correlation rule: {str(e)}"
            self.logger.error(error_msg)
            raise CorrelationError(error_msg)

    async def process_event(
        self,
        session: AsyncSession,
        event_data: Dict[str, Any]
    ) -> List[CorrelationEvent]:
        """Process an event and generate correlation events."""
        try:
            # Get active rules
            rules = await correlation_rule_repository.get_active_rules(session)
            correlation_events = []

            for rule in rules:
                try:
                    # Apply rule logic
                    if await self._matches_rule(session, rule, event_data):
                        correlation_event = CorrelationEvent(
                            rule_id=rule.id,
                            source_events=[event_data],
                            timestamp=datetime.utcnow(),
                            severity=rule.severity
                        )
                        correlation_events.append(correlation_event)
                except Exception as e:
                    self.logger.warning(
                        f"Failed to apply rule {rule.id} to event: {str(e)}"
                    )
                    continue

            # Create correlation events
            if correlation_events:
                created_events = await correlation_event_repository.bulk_create(
                    session, correlation_events
                )
                self.logger.info(
                    f"Generated {len(created_events)} correlation events"
                )
                return created_events
            return []
        except Exception as e:
            error_msg = f"Failed to process event: {str(e)}"
            self.logger.error(error_msg)
            raise EventProcessingError(error_msg)

    async def _matches_rule(
        self,
        session: AsyncSession,
        rule: CorrelationRule,
        event_data: Dict[str, Any]
    ) -> bool:
        """Check if an event matches a correlation rule."""
        try:
            if rule.rule_type == CorrelationRuleType.THRESHOLD:
                return await self._check_threshold(session, rule, event_data)
            elif rule.rule_type == CorrelationRuleType.SEQUENCE:
                return await self._check_sequence(session, rule, event_data)
            elif rule.rule_type == CorrelationRuleType.PATTERN:
                return await self._check_pattern(rule, event_data)
            elif rule.rule_type == CorrelationRuleType.AGGREGATION:
                return await self._check_aggregation(session, rule, event_data)
            elif rule.rule_type == CorrelationRuleType.ANOMALY:
                return await self._check_anomaly(session, rule, event_data)
            return False
        except Exception as e:
            self.logger.warning(f"Rule matching failed: {str(e)}")
            return False

    async def _check_threshold(
        self,
        session: AsyncSession,
        rule: CorrelationRule,
        event_data: Dict[str, Any]
    ) -> bool:
        """Check threshold-based correlation rule."""
        try:
            threshold = rule.config["threshold"]
            timeframe = rule.config["timeframe"]
            start_time = datetime.utcnow() - timedelta(minutes=timeframe)

            # Count similar events in timeframe
            count = await correlation_event_repository.count_similar_events(
                session,
                rule.id,
                event_data,
                start_time
            )

            return count >= threshold
        except Exception as e:
            self.logger.warning(f"Threshold check failed: {str(e)}")
            return False

    async def _check_sequence(
        self,
        session: AsyncSession,
        rule: CorrelationRule,
        event_data: Dict[str, Any]
    ) -> bool:
        """Check sequence-based correlation rule."""
        try:
            events = rule.config["events"]
            max_gap = rule.config["max_gap"]
            start_time = datetime.utcnow() - timedelta(minutes=max_gap)

            # Get recent events
            recent_events = await correlation_event_repository.get_recent_events(
                session,
                rule.id,
                start_time
            )

            # Check if sequence matches
            return self._match_sequence(events, recent_events + [event_data])
        except Exception as e:
            self.logger.warning(f"Sequence check failed: {str(e)}")
            return False

    def _check_pattern(
        self,
        rule: CorrelationRule,
        event_data: Dict[str, Any]
    ) -> bool:
        """Check pattern-based correlation rule."""
        try:
            pattern = rule.config["pattern"]
            conditions = rule.config["conditions"]

            # Check if event matches pattern and conditions
            return self._match_pattern(pattern, conditions, event_data)
        except Exception as e:
            self.logger.warning(f"Pattern check failed: {str(e)}")
            return False

    async def _check_aggregation(
        self,
        session: AsyncSession,
        rule: CorrelationRule,
        event_data: Dict[str, Any]
    ) -> bool:
        """Check aggregation-based correlation rule."""
        try:
            group_by = rule.config["group_by"]
            metrics = rule.config["metrics"]

            # Get aggregated metrics
            agg_metrics = await correlation_event_repository.get_aggregated_metrics(
                session,
                rule.id,
                group_by,
                metrics
            )

            # Check if metrics match conditions
            return self._match_metrics(metrics, agg_metrics)
        except Exception as e:
            self.logger.warning(f"Aggregation check failed: {str(e)}")
            return False

    async def _check_anomaly(
        self,
        session: AsyncSession,
        rule: CorrelationRule,
        event_data: Dict[str, Any]
    ) -> bool:
        """Check anomaly-based correlation rule."""
        try:
            baseline = rule.config["baseline"]
            sensitivity = rule.config["sensitivity"]

            # Get baseline metrics
            baseline_metrics = await correlation_event_repository.get_baseline_metrics(
                session,
                rule.id,
                baseline
            )

            # Check if event deviates from baseline
            return self._detect_anomaly(baseline_metrics, event_data, sensitivity)
        except Exception as e:
            self.logger.warning(f"Anomaly check failed: {str(e)}")
            return False

    async def analyze_event_chain(
        self,
        session: AsyncSession,
        event_id: UUID
    ) -> Optional[EventChain]:
        """Analyze the correlation chain for an event."""
        try:
            event = await correlation_event_repository.get(session, event_id)
            if not event:
                raise CorrelationError(f"Event {event_id} not found")

            # Get related events
            related_events = await correlation_event_repository.get_related_events(
                session,
                event_id,
                max_depth=3
            )

            # Build event chain
            chain = EventChain(
                root_event_id=event_id,
                events=related_events,
                confidence=self._calculate_chain_confidence(related_events),
                last_seen=datetime.utcnow()
            )

            chain = await event_chain_repository.create(session, chain)
            self.logger.info(f"Created event chain for event {event_id}")
            return chain
        except Exception as e:
            error_msg = f"Failed to analyze event chain: {str(e)}"
            self.logger.error(error_msg)
            raise CorrelationError(error_msg)

    def _calculate_chain_confidence(
        self,
        events: List[CorrelationEvent]
    ) -> float:
        """Calculate confidence score for an event chain."""
        try:
            if not events:
                return 0.0

            # Calculate confidence based on:
            # - Number of related events
            # - Severity of events
            # - Temporal proximity
            # - Rule effectiveness (true positive ratio)

            # This is a simplified implementation
            base_score = min(len(events) / 10.0, 1.0)
            severity_score = sum(e.severity.value for e in events) / (len(events) * 3.0)
            
            return (base_score + severity_score) / 2.0
        except Exception as e:
            self.logger.warning(f"Confidence calculation failed: {str(e)}")
            return 0.0

    async def get_rule_effectiveness(
        self,
        session: AsyncSession,
        rule_id: UUID
    ) -> Dict[str, Any]:
        """Get effectiveness metrics for a correlation rule."""
        try:
            metrics = await correlation_rule_repository.get_rule_metrics(
                session,
                rule_id
            )

            total = metrics["true_positives"] + metrics["false_positives"]
            accuracy = metrics["true_positives"] / total if total > 0 else 0

            return {
                "rule_id": rule_id,
                "true_positives": metrics["true_positives"],
                "false_positives": metrics["false_positives"],
                "accuracy": accuracy,
                "last_triggered": metrics["last_triggered"],
                "total_triggers": total
            }
        except Exception as e:
            error_msg = f"Failed to get rule effectiveness: {str(e)}"
            self.logger.error(error_msg)
            raise CorrelationError(error_msg)

# Create service instance
correlation_service = CorrelationService() 