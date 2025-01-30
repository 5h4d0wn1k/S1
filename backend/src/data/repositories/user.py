from typing import Optional, List
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .base import BaseRepository
from ..models.user import User, Role

class UserRepository(BaseRepository[User]):
    """User repository."""
    
    def __init__(self) -> None:
        """Initialize repository."""
        super().__init__(User)
    
    async def get_by_username(
        self,
        session: AsyncSession,
        username: str
    ) -> Optional[User]:
        """Get user by username."""
        try:
            stmt = self.select().where(User.username == username)
            result = await session.execute(stmt)
            return result.scalar_one_or_none()
        except Exception as e:
            self.log_error(
                "Failed to get user by username",
                error=e,
                username=username
            )
            raise
    
    async def get_by_email(
        self,
        session: AsyncSession,
        email: str
    ) -> Optional[User]:
        """Get user by email."""
        try:
            stmt = self.select().where(User.email == email)
            result = await session.execute(stmt)
            return result.scalar_one_or_none()
        except Exception as e:
            self.log_error(
                "Failed to get user by email",
                error=e,
                email=email
            )
            raise
    
    async def get_by_api_key(
        self,
        session: AsyncSession,
        api_key: str
    ) -> Optional[User]:
        """Get user by API key."""
        try:
            stmt = self.select().where(
                User.api_key == api_key,
                User.api_key_expires_at > datetime.utcnow()
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()
        except Exception as e:
            self.log_error(
                "Failed to get user by API key",
                error=e
            )
            raise
    
    async def get_active_users(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[User]:
        """Get active users."""
        try:
            stmt = (
                self.select()
                .where(User.is_active == True)
                .offset(skip)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get active users",
                error=e,
                skip=skip,
                limit=limit
            )
            raise
    
    async def get_superusers(
        self,
        session: AsyncSession
    ) -> List[User]:
        """Get superusers."""
        try:
            stmt = self.select().where(User.is_superuser == True)
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error("Failed to get superusers", error=e)
            raise

class RoleRepository(BaseRepository[Role]):
    """Role repository."""
    
    def __init__(self) -> None:
        """Initialize repository."""
        super().__init__(Role)
    
    async def get_by_name(
        self,
        session: AsyncSession,
        name: str
    ) -> Optional[Role]:
        """Get role by name."""
        try:
            stmt = self.select().where(Role.name == name)
            result = await session.execute(stmt)
            return result.scalar_one_or_none()
        except Exception as e:
            self.log_error(
                "Failed to get role by name",
                error=e,
                name=name
            )
            raise
    
    async def get_user_roles(
        self,
        session: AsyncSession,
        user_id: int
    ) -> List[Role]:
        """Get roles for user."""
        try:
            stmt = (
                self.select()
                .join(User.role)
                .where(User.id == user_id)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            self.log_error(
                "Failed to get user roles",
                error=e,
                user_id=user_id
            )
            raise

# Create repository instances
user_repository = UserRepository()
role_repository = RoleRepository() 