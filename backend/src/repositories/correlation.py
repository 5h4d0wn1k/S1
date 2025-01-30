from datetime import datetime, timedelta
from typing import List, Optional, Dict
from uuid import UUID

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

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

class CorrelationRuleRepository(BaseRepository[CorrelationRule, CorrelationRule, CorrelationRule]):
    """Repository for correlation rules."""
    
    def __init__(self):
        """Initialize repository with CorrelationRule model."""
        super().__init__(CorrelationRule)
    
    async def get_active_rules(
        self,
        session: AsyncSession
    ) -> List[CorrelationRule]:
        """Get active correlation rules."""
        result = await session.execute(
            select(self.model)
            .where(self.model.status == CorrelationRuleStatus.ACTIVE)
        )
        return result.scalars().all()
    
    async def get_rules_by_type(
        self,
        session: AsyncSession,
        rule_type: CorrelationRuleType
    ) -> List[CorrelationRule]:
        """Get correlation rules by type."""
        result = await session.execute(
            select(self.model)
            .where(self.model.rule_type == rule_type)
        )
        return result.scalars().all()
    
    async def get_rules_by_severity(
        self,
        session: AsyncSession,
        severity: CorrelationSeverity
    ) -> List[CorrelationRule]:
        """Get correlation rules by severity."""
        result = await session.execute(
            select(self.model)
            .where(self.model.severity == severity)
        )
        return result.scalars().all()
    
    async def get_rule_counts_by_type(
        self,
        session: AsyncSession
    ) -> Dict[str, int]:
        """Get rule counts by type."""
        result = await session.execute(
            select(self.model.rule_type, self.model.id)
        )
        counts = {}
        for row in result:
            rule_type = row[0]
            counts[rule_type] = counts.get(rule_type, 0) + 1
        return counts

class CorrelationEventRepository(BaseRepository[CorrelationEvent, CorrelationEvent, CorrelationEvent]):
    """Repository for correlation events."""
    
    def __init__(self):
        """Initialize repository with CorrelationEvent model."""
        super().__init__(CorrelationEvent)
    
    async def get_events_by_rule(
        self,
        session: AsyncSession,
        rule_id: UUID,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CorrelationEvent]:
        """Get correlation events by rule ID."""
        result = await session.execute(
            select(self.model)
            .where(self.model.rule_id == rule_id)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_events_by_severity(
        self,
        session: AsyncSession,
        severity: CorrelationSeverity,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CorrelationEvent]:
        """Get correlation events by severity."""
        result = await session.execute(
            select(self.model)
            .where(self.model.severity == severity)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_events_by_timerange(
        self,
        session: AsyncSession,
        start_time: datetime,
        end_time: datetime,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CorrelationEvent]:
        """Get correlation events within time range."""
        result = await session.execute(
            select(self.model)
            .where(
                and_(
                    self.model.created_at >= start_time,
                    self.model.created_at <= end_time
                )
            )
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_false_positives(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CorrelationEvent]:
        """Get false positive correlation events."""
        result = await session.execute(
            select(self.model)
            .where(self.model.false_positive == True)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

class EventChainRepository(BaseRepository[EventChain, EventChain, EventChain]):
    """Repository for event chains."""
    
    def __init__(self):
        """Initialize repository with EventChain model."""
        super().__init__(EventChain)
    
    async def get_chains_by_root_event(
        self,
        session: AsyncSession,
        root_event_id: UUID
    ) -> List[EventChain]:
        """Get event chains by root event ID."""
        result = await session.execute(
            select(self.model)
            .where(self.model.root_event_id == root_event_id)
        )
        return result.scalars().all()
    
    async def get_chains_by_severity(
        self,
        session: AsyncSession,
        severity: CorrelationSeverity,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[EventChain]:
        """Get event chains by severity."""
        result = await session.execute(
            select(self.model)
            .where(self.model.severity == severity)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_chains_by_confidence(
        self,
        session: AsyncSession,
        min_confidence: float,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[EventChain]:
        """Get event chains by minimum confidence."""
        result = await session.execute(
            select(self.model)
            .where(self.model.confidence >= min_confidence)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

class CampaignPatternRepository(BaseRepository[CampaignPattern, CampaignPattern, CampaignPattern]):
    """Repository for campaign patterns."""
    
    def __init__(self):
        """Initialize repository with CampaignPattern model."""
        super().__init__(CampaignPattern)
    
    async def get_active_campaigns(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CampaignPattern]:
        """Get active campaign patterns."""
        current_time = datetime.utcnow()
        result = await session.execute(
            select(self.model)
            .where(
                and_(
                    self.model.first_seen <= current_time,
                    self.model.last_seen >= current_time
                )
            )
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_campaigns_by_confidence(
        self,
        session: AsyncSession,
        min_confidence: float,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CampaignPattern]:
        """Get campaign patterns by minimum confidence."""
        result = await session.execute(
            select(self.model)
            .where(self.model.confidence >= min_confidence)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_related_campaigns(
        self,
        session: AsyncSession,
        campaign_id: UUID
    ) -> List[CampaignPattern]:
        """Get related campaign patterns."""
        result = await session.execute(
            select(self.model)
            .where(self.model.related_campaigns.contains([campaign_id]))
        )
        return result.scalars().all()

# Create repository instances
correlation_rule_repository = CorrelationRuleRepository()
correlation_event_repository = CorrelationEventRepository()
event_chain_repository = EventChainRepository()
campaign_pattern_repository = CampaignPatternRepository() 