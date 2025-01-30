from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from ..models.campaign import (
    CampaignPattern,
    CampaignIndicator,
    CampaignTactic,
    CampaignThreatActor,
    CampaignStatus,
    CampaignConfidenceLevel
)
from .base import BaseRepository
from ..utils.logging import LoggerMixin
from ..core.exceptions import DatabaseError

class CampaignPatternRepository(BaseRepository[CampaignPattern], LoggerMixin):
    """Repository for managing campaign patterns."""

    def __init__(self):
        """Initialize the repository with CampaignPattern model."""
        super().__init__(CampaignPattern)
        self.logger.info("Initialized CampaignPatternRepository")

    async def get_active_campaigns(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CampaignPattern]:
        """Get active campaign patterns with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.status == CampaignStatus.ACTIVE)
                .order_by(self.model.last_seen.desc())
                .offset(skip)
                .limit(limit)
            )
            campaigns = result.scalars().all()
            self.logger.debug(f"Retrieved {len(campaigns)} active campaigns")
            return campaigns
        except SQLAlchemyError as e:
            error_msg = f"Failed to get active campaigns: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

    async def get_campaigns_by_confidence(
        self,
        session: AsyncSession,
        min_confidence: CampaignConfidenceLevel,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CampaignPattern]:
        """Get campaign patterns by minimum confidence level with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.confidence_level >= min_confidence)
                .order_by(self.model.confidence_level.desc())
                .offset(skip)
                .limit(limit)
            )
            campaigns = result.scalars().all()
            self.logger.debug(f"Retrieved {len(campaigns)} campaigns with min confidence {min_confidence}")
            return campaigns
        except SQLAlchemyError as e:
            error_msg = f"Failed to get campaigns by confidence {min_confidence}: {str(e)}"
            self.logger.error(error_msg)
            raise DatabaseError(error_msg)

    async def get_related_campaigns(
        self,
        session: AsyncSession,
        campaign_id: UUID,
        min_similarity: float = 0.7
    ) -> List[CampaignPattern]:
        """Get related campaign patterns based on similarity score."""
        try:
            campaign = await self.get(session, campaign_id)
            if not campaign:
                return []

            # Get campaigns with similar indicators or tactics
            result = await session.execute(
                select(self.model)
                .where(
                    and_(
                        self.model.id != campaign_id,
                        or_(
                            self.model.indicators.overlap(campaign.indicators),
                            self.model.tactics.overlap(campaign.tactics)
                        ),
                        self.model.similarity_score >= min_similarity
                    )
                )
                .order_by(self.model.similarity_score.desc())
            )
            related = result.scalars().all()
            self.logger.debug(f"Retrieved {len(related)} related campaigns for {campaign_id}")
            return related
        except SQLAlchemyError as e:
            error_msg = f"Failed to get related campaigns for {campaign_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_campaign_statistics(
        self,
        session: AsyncSession,
        timeframe_minutes: int = 1440
    ) -> Dict[str, Any]:
        """Get campaign pattern statistics."""
        try:
            start_time = datetime.utcnow() - timedelta(minutes=timeframe_minutes)
            
            # Get counts by status
            status_counts = await session.execute(
                select(
                    self.model.status,
                    func.count(self.model.id)
                )
                .where(self.model.last_seen >= start_time)
                .group_by(self.model.status)
            )
            
            # Get counts by confidence level
            confidence_counts = await session.execute(
                select(
                    self.model.confidence_level,
                    func.count(self.model.id)
                )
                .where(self.model.last_seen >= start_time)
                .group_by(self.model.confidence_level)
            )
            
            # Get most common tactics
            tactic_counts = await session.execute(
                select(
                    func.unnest(self.model.tactics).label('tactic'),
                    func.count(self.model.id)
                )
                .where(self.model.last_seen >= start_time)
                .group_by('tactic')
                .order_by(func.count(self.model.id).desc())
                .limit(10)
            )

            return {
                "status_counts": dict(status_counts.all()),
                "confidence_counts": dict(confidence_counts.all()),
                "top_tactics": dict(tactic_counts.all()),
                "timeframe_minutes": timeframe_minutes
            }
        except SQLAlchemyError as e:
            error_msg = "Failed to get campaign statistics"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

class CampaignIndicatorRepository(BaseRepository[CampaignIndicator], LoggerMixin):
    """Repository for managing campaign indicators."""

    def __init__(self):
        """Initialize the repository with CampaignIndicator model."""
        super().__init__(CampaignIndicator)
        self.logger.info("Initialized CampaignIndicatorRepository")

    async def get_indicators_by_campaign(
        self,
        session: AsyncSession,
        campaign_id: UUID,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CampaignIndicator]:
        """Get campaign indicators by campaign ID with pagination."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.campaign_id == campaign_id)
                .order_by(self.model.created_at.desc())
                .offset(skip)
                .limit(limit)
            )
            indicators = result.scalars().all()
            self.logger.debug(f"Retrieved {len(indicators)} indicators for campaign {campaign_id}")
            return indicators
        except SQLAlchemyError as e:
            error_msg = f"Failed to get indicators for campaign {campaign_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_shared_indicators(
        self,
        session: AsyncSession,
        campaign_ids: List[UUID]
    ) -> List[CampaignIndicator]:
        """Get indicators shared between multiple campaigns."""
        try:
            if not campaign_ids:
                return []

            # Get indicators that appear in all specified campaigns
            subquery = (
                select(self.model.indicator_value)
                .where(self.model.campaign_id.in_(campaign_ids))
                .group_by(self.model.indicator_value)
                .having(func.count(distinct(self.model.campaign_id)) == len(campaign_ids))
            )

            result = await session.execute(
                select(self.model)
                .where(self.model.indicator_value.in_(subquery))
                .order_by(self.model.created_at.desc())
            )
            indicators = result.scalars().all()
            self.logger.debug(f"Retrieved {len(indicators)} shared indicators between campaigns")
            return indicators
        except SQLAlchemyError as e:
            error_msg = "Failed to get shared indicators"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

class CampaignThreatActorRepository(BaseRepository[CampaignThreatActor], LoggerMixin):
    """Repository for managing campaign threat actors."""

    def __init__(self):
        """Initialize the repository with CampaignThreatActor model."""
        super().__init__(CampaignThreatActor)
        self.logger.info("Initialized CampaignThreatActorRepository")

    async def get_actors_by_campaign(
        self,
        session: AsyncSession,
        campaign_id: UUID,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CampaignThreatActor]:
        """Get threat actors associated with a campaign."""
        try:
            result = await session.execute(
                select(self.model)
                .where(self.model.campaign_id == campaign_id)
                .order_by(self.model.confidence_level.desc())
                .offset(skip)
                .limit(limit)
            )
            actors = result.scalars().all()
            self.logger.debug(f"Retrieved {len(actors)} threat actors for campaign {campaign_id}")
            return actors
        except SQLAlchemyError as e:
            error_msg = f"Failed to get threat actors for campaign {campaign_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

    async def get_actor_campaigns(
        self,
        session: AsyncSession,
        actor_id: UUID,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[CampaignPattern]:
        """Get campaigns associated with a threat actor."""
        try:
            result = await session.execute(
                select(CampaignPattern)
                .join(self.model, self.model.campaign_id == CampaignPattern.id)
                .where(self.model.actor_id == actor_id)
                .order_by(CampaignPattern.last_seen.desc())
                .offset(skip)
                .limit(limit)
            )
            campaigns = result.scalars().all()
            self.logger.debug(f"Retrieved {len(campaigns)} campaigns for actor {actor_id}")
            return campaigns
        except SQLAlchemyError as e:
            error_msg = f"Failed to get campaigns for actor {actor_id}"
            self.logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseError(error_msg)

# Create repository instances
campaign_pattern_repository = CampaignPatternRepository()
campaign_indicator_repository = CampaignIndicatorRepository()
campaign_threat_actor_repository = CampaignThreatActorRepository() 