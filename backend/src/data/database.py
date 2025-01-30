from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from elasticsearch import AsyncElasticsearch
from redis import asyncio as aioredis
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine
)
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)

from ..core.exceptions import DatabaseError
from ..core.settings import get_settings
from ..utils.logging import LoggerMixin

settings = get_settings()

class DatabaseManager(LoggerMixin):
    """Manages database connections and sessions."""
    
    def __init__(self) -> None:
        self.engine: Optional[AsyncEngine] = None
        self.async_session_maker: Optional[async_sessionmaker] = None
        self.elasticsearch: Optional[AsyncElasticsearch] = None
        self.redis: Optional[aioredis.Redis] = None
        
        # Initialize connections
        self._init_postgres()
        self._init_elasticsearch()
        self._init_redis()
    
    def _init_postgres(self) -> None:
        """Initialize PostgreSQL connection."""
        try:
            self.engine = create_async_engine(
                settings.POSTGRES_URL,
                echo=settings.DEBUG,
                pool_size=20,
                max_overflow=10,
                pool_timeout=30,
                pool_recycle=1800,
            )
            self.async_session_maker = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )
        except Exception as e:
            self.log_error("Failed to initialize PostgreSQL", e)
            raise DatabaseError("PostgreSQL initialization failed", details={"error": str(e)})
    
    def _init_elasticsearch(self) -> None:
        """Initialize Elasticsearch connection."""
        try:
            self.elasticsearch = AsyncElasticsearch(
                settings.ELASTICSEARCH_URL,
                retry_on_timeout=True,
                max_retries=3,
            )
        except Exception as e:
            self.log_error("Failed to initialize Elasticsearch", e)
            raise DatabaseError("Elasticsearch initialization failed", details={"error": str(e)})
    
    def _init_redis(self) -> None:
        """Initialize Redis connection."""
        try:
            self.redis = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                max_connections=20,
            )
        except Exception as e:
            self.log_error("Failed to initialize Redis", e)
            raise DatabaseError("Redis initialization failed", details={"error": str(e)})
    
    @asynccontextmanager
    async def get_db_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session with automatic cleanup."""
        if not self.async_session_maker:
            raise DatabaseError("Database session maker not initialized")
        
        session: AsyncSession = self.async_session_maker()
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            self.log_error("Database session error", e)
            raise DatabaseError("Database operation failed", details={"error": str(e)})
        finally:
            await session.close()
    
    @retry(
        retry=retry_if_exception_type(DatabaseError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        reraise=True
    )
    async def execute_with_retry(self, session: AsyncSession, operation: str, *args, **kwargs):
        """Execute a database operation with retry logic."""
        try:
            result = await getattr(session, operation)(*args, **kwargs)
            return result
        except Exception as e:
            self.log_error(f"Database operation '{operation}' failed", e)
            raise DatabaseError(
                f"Database operation '{operation}' failed",
                details={"error": str(e), "operation": operation}
            )
    
    async def close(self) -> None:
        """Close all database connections."""
        if self.engine:
            await self.engine.dispose()
        
        if self.elasticsearch:
            await self.elasticsearch.close()
        
        if self.redis:
            await self.redis.close()
        
        self.log_info("All database connections closed")

# Global database manager instance
db_manager = DatabaseManager()

# Dependency for FastAPI
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for database sessions."""
    async with db_manager.get_db_session() as session:
        yield session

# Elasticsearch dependency
async def get_elasticsearch() -> AsyncElasticsearch:
    """FastAPI dependency for Elasticsearch client."""
    return db_manager.elasticsearch

# Redis dependency
async def get_redis() -> aioredis.Redis:
    """FastAPI dependency for Redis client."""
    return db_manager.redis 