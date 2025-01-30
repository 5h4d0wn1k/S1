from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from .connectors.postgres import postgres_connector

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get database session."""
    async with postgres_connector.session() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            raise
        finally:
            await session.close()

async def get_db_transaction() -> AsyncGenerator[AsyncSession, None]:
    """Get database transaction."""
    async with postgres_connector.transaction() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            raise
        finally:
            await session.close() 