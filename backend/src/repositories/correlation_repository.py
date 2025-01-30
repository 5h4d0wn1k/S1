from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from ..models.correlation import (
    CorrelationRule,
    CorrelationEvent,
    EventChain,
    CampaignPattern,
    CorrelationRuleType,
    CorrelationRuleStatus,
    CorrelationSeverity
)
from .base import BaseRepository
from ..utils.logging import LoggerMixin
from ..core.exceptions import DatabaseError

class CorrelationRuleRepository(BaseRepository[CorrelationRule], LoggerMixin):
    """Repository for managing correlation rules."""

    def __init__(self):
        """Initialize the repository with CorrelationRule model."""
        super().__init__(CorrelationRule)
        self.logger.info("Initialized CorrelationRuleRepository")

    async def get_active_rules(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CorrelationRule]:
        """Get active correlation rules with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.status == CorrelationRuleStatus.ACTIVE)
                .offset(skip)
                .limit(limit)
            )
            rules = result.scalars().all()
            self.logger.debug(f"Retrieved {len(rules)} active correlation rules")
            return rules
        except SQLAlchemyError as e:
            error_msg = f"Failed to get active correlation rules: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

    async def get_rules_by_type(
        self,
        session: AsyncSession,
        rule_type: CorrelationRuleType,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CorrelationRule]:
        """Get correlation rules by type with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.rule_type == rule_type)
                .offset(skip)
                .limit(limit)
            )
            rules = result.scalars().all()
            self.logger.debug(f"Retrieved {len(rules)} rules of type {rule_type}")
            return rules
        except SQLAlchemyError as e:
            error_msg = f"Failed to get correlation rules by type {rule_type}: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

    async def get_rules_by_severity(
        self,
        session: AsyncSession,
        severity: CorrelationSeverity,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CorrelationRule]:
        """Get correlation rules by severity with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.severity == severity)
                .offset(skip)
                .limit(limit)
            )
            rules = result.scalars().all()
            self.logger.debug(f"Retrieved {len(rules)} rules with severity {severity}")
            return rules
        except SQLAlchemyError as e:
            error_msg = f"Failed to get correlation rules by severity {severity}: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

    async def get_rules_by_effectiveness(
        self,
        session: AsyncSession,
        min_true_positives: int = 1,
        max_false_positives: int = 10,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CorrelationRule]:
        """Get effective correlation rules based on true/false positive ratios."""
        try:
            result = await session.execute(
                select(self.model)
                .where(
                    and_(
                        self.model.true_positives >= min_true_positives,
                        self.model.false_positives <= max_false_positives
                    )
                )
                .offset(skip)
                .limit(limit)
            )
            rules = result.scalars().all()
            self.logger.debug(f"Retrieved {len(rules)} effective correlation rules")
            return rules
        except SQLAlchemyError as e:
            error_msg = "Failed to get correlation rules by effectiveness metrics"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_rule_metrics(
        self,
        session: AsyncSession,
        rule_id: UUID
    ) -> Dict[str, Any]:
        """Get performance metrics for a specific correlation rule."""
        try:
            result = await session.execute(
                select(
                    self.model.true_positives,
                    self.model.false_positives,
                    self.model.last_triggered
                ).where(self.model.id == rule_id)
            )
            metrics = result.first()
            if not metrics:
                error_msg = f"Rule with ID {rule_id} not found"
                self.logger.error(error_msg)
                raise DatabaseError(error_msg)

            true_pos, false_pos, last_triggered = metrics
            total = true_pos + false_pos
            accuracy = true_pos / total if total > 0 else 0

            return {
                "true_positives": true_pos,
                "false_positives": false_pos,
                "accuracy": accuracy,
                "last_triggered": last_triggered,
                "total_triggers": total
            }
        except SQLAlchemyError as e:
            error_msg = f"Failed to get metrics for rule {rule_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

class CorrelationEventRepository(BaseRepository[CorrelationEvent], LoggerMixin):
    """Repository for managing correlation events."""

    def __init__(self):
        """Initialize the repository with CorrelationEvent model."""
        super().__init__(CorrelationEvent)
        self.logger.info("Initialized CorrelationEventRepository")

    async def get_events_by_rule(
        self,
        session: AsyncSession,
        rule_id: UUID,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CorrelationEvent]:
        """Get correlation events by rule ID with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.rule_id == rule_id)
                .order_by(self.model.created_at.desc())
                .offset(skip)
                .limit(limit)
            )
            events = result.scalars().all()
            self.logger.debug(f"Retrieved {len(events)} events for rule {rule_id}")
            return events
        except SQLAlchemyError as e:
            error_msg = f"Failed to get correlation events for rule {rule_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_events_by_timerange(
        self,
        session: AsyncSession,
        start_time: datetime,
        end_time: datetime,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CorrelationEvent]:
        """Get correlation events within a time range with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(
                    and_(
                        self.model.created_at >= start_time,
                        self.model.created_at <= end_time
                    )
                )
                .order_by(self.model.created_at.desc())
                .offset(skip)
                .limit(limit)
            )
            events = result.scalars().all()
            self.logger.debug(
                f"Retrieved {len(events)} events between {start_time} and {end_time}"
            )
            return events
        except SQLAlchemyError as e:
            error_msg = "Failed to get correlation events by time range"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_related_events(
        self,
        session: AsyncSession,
        event_id: UUID,
        max_depth: int = 3
    ) -> List[CorrelationEvent]:
        """Get related correlation events up to a specified depth."""
        try:
            # Start with the initial event
            event = await self.get(session, event_id)
            if not event:
                return []

            related_events = []
            processed_ids = {event_id}
            current_depth = 0
            current_level = [event]

            while current_level and current_depth < max_depth:
                next_level = []
                for current_event in current_level:
                    # Get events that share common source events
                    result = await session.execute(
                        select(self.model)
                        .where(
                            or_(
                                self.model.source_events.overlap(
                                    current_event.source_events
                                ),
                                self.model.alert_ids.overlap(
                                    current_event.alert_ids
                                )
                            )
                        )
                    )
                    related = result.scalars().all()
                    
                    for rel_event in related:
                        if rel_event.id not in processed_ids:
                            next_level.append(rel_event)
                            related_events.append(rel_event)
                            processed_ids.add(rel_event.id)

                current_level = next_level
                current_depth += 1

            self.logger.debug(
                f"Retrieved {len(related_events)} related events for event {event_id}"
            )
            return related_events
        except SQLAlchemyError as e:
            error_msg = f"Failed to get related events for event {event_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

class EventChainRepository(BaseRepository[EventChain], LoggerMixin):
    """Repository for managing event chains."""

    def __init__(self):
        """Initialize the repository with EventChain model."""
        super().__init__(EventChain)
        self.logger.info("Initialized EventChainRepository")

    async def get_active_chains(
        self,
        session: AsyncSession,
        *,
        min_confidence: float = 0.7,
        skip: int = 0,
        limit: int = 100
    ) -> List[EventChain]:
        """Get active event chains with high confidence."""
        try:
            current_time = datetime.utcnow()
            result = await session.execute(
                select(self.model)
                .where(
                    and_(
                        self.model.confidence >= min_confidence,
                        self.model.last_seen >= current_time - timedelta(hours=24)
                    )
                )
                .order_by(self.model.confidence.desc())
                .offset(skip)
                .limit(limit)
            )
            chains = result.scalars().all()
            self.logger.debug(f"Retrieved {len(chains)} active event chains")
            return chains
        except SQLAlchemyError as e:
            error_msg = "Failed to get active event chains"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_chain_by_root_event(
        self,
        session: AsyncSession,
        root_event_id: UUID
    ) -> Optional[EventChain]:
        """Get event chain by root event ID."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.root_event_id == root_event_id)
            )
            chain = result.scalar_one_or_none()
            if chain:
                self.logger.debug(f"Retrieved chain for root event {root_event_id}")
            else:
                self.logger.debug(f"No chain found for root event {root_event_id}")
            return chain
        except SQLAlchemyError as e:
            error_msg = f"Failed to get event chain for root event {root_event_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

# Create repository instances
correlation_rule_repository = CorrelationRuleRepository()
correlation_event_repository = CorrelationEventRepository()
event_chain_repository = EventChainRepository() 