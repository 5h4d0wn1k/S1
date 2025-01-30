from typing import Dict, List, Optional, Union, Any
from datetime import datetime
import json

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import text
from sqlalchemy.exc import SQLAlchemyError

from ...core.settings import get_settings
from ...utils.logging import LoggerMixin

settings = get_settings()

class PostgresConnector(LoggerMixin):
    """PostgreSQL connector for storing relational data."""
    
    def __init__(self):
        """Initialize PostgreSQL connection."""
        super().__init__()
        self.engine = None
        self.session_factory = None
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize database connection and session factory."""
        try:
            # Create async engine
            self.engine = create_async_engine(
                f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
                f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}",
                echo=settings.DEBUG,  # SQL logging
                pool_size=settings.POSTGRES_POOL_SIZE,
                max_overflow=settings.POSTGRES_MAX_OVERFLOW,
                pool_timeout=settings.POSTGRES_POOL_TIMEOUT
            )
            
            # Create session factory
            self.session_factory = sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            self.log_info("PostgreSQL connection initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize PostgreSQL connection", error=e)
            raise
    
    async def execute_query(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Execute a raw SQL query."""
        async with self.session_factory() as session:
            try:
                result = await session.execute(text(query), params or {})
                
                if result.returns_rows:
                    # Convert result to list of dictionaries
                    columns = result.keys()
                    return [dict(zip(columns, row)) for row in result.fetchall()]
                return []
                
            except Exception as e:
                self.log_error(
                    "Failed to execute query",
                    error=e,
                    query=query,
                    params=params
                )
                raise
    
    async def execute_transaction(
        self,
        queries: List[Dict[str, Any]]
    ) -> bool:
        """Execute multiple queries in a transaction."""
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    for query in queries:
                        await session.execute(
                            text(query["query"]),
                            query.get("params", {})
                        )
                return True
                
            except Exception as e:
                self.log_error(
                    "Failed to execute transaction",
                    error=e,
                    queries=queries
                )
                raise
    
    async def insert(
        self,
        table: str,
        data: Dict[str, Any]
    ) -> Optional[int]:
        """Insert a single row into a table."""
        columns = ", ".join(data.keys())
        placeholders = ", ".join(f":{k}" for k in data.keys())
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders}) RETURNING id"
        
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    result = await session.execute(text(query), data)
                    return result.scalar_one()
                    
            except Exception as e:
                self.log_error(
                    "Failed to insert data",
                    error=e,
                    table=table,
                    data=data
                )
                raise
    
    async def bulk_insert(
        self,
        table: str,
        data: List[Dict[str, Any]]
    ) -> int:
        """Insert multiple rows into a table."""
        if not data:
            return 0
            
        # Get columns from first row
        columns = list(data[0].keys())
        placeholders = ", ".join(f":{col}" for col in columns)
        query = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
        
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    for row in data:
                        await session.execute(text(query), row)
                    return len(data)
                    
            except Exception as e:
                self.log_error(
                    "Failed to bulk insert data",
                    error=e,
                    table=table,
                    row_count=len(data)
                )
                raise
    
    async def update(
        self,
        table: str,
        data: Dict[str, Any],
        where: Dict[str, Any]
    ) -> int:
        """Update rows in a table."""
        set_clause = ", ".join(f"{k} = :{k}" for k in data.keys())
        where_clause = " AND ".join(f"{k} = :{k}_where" for k in where.keys())
        
        query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
        
        # Combine parameters with renamed where clause parameters
        params = {
            **data,
            **{f"{k}_where": v for k, v in where.items()}
        }
        
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    result = await session.execute(text(query), params)
                    return result.rowcount
                    
            except Exception as e:
                self.log_error(
                    "Failed to update data",
                    error=e,
                    table=table,
                    data=data,
                    where=where
                )
                raise
    
    async def delete(
        self,
        table: str,
        where: Dict[str, Any]
    ) -> int:
        """Delete rows from a table."""
        where_clause = " AND ".join(f"{k} = :{k}" for k in where.keys())
        query = f"DELETE FROM {table} WHERE {where_clause}"
        
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    result = await session.execute(text(query), where)
                    return result.rowcount
                    
            except Exception as e:
                self.log_error(
                    "Failed to delete data",
                    error=e,
                    table=table,
                    where=where
                )
                raise
    
    async def get_by_id(
        self,
        table: str,
        id_: Union[int, str],
        columns: Optional[List[str]] = None
    ) -> Optional[Dict[str, Any]]:
        """Get a single row by ID."""
        cols = ", ".join(columns) if columns else "*"
        query = f"SELECT {cols} FROM {table} WHERE id = :id"
        
        async with self.session_factory() as session:
            try:
                result = await session.execute(text(query), {"id": id_})
                row = result.first()
                return dict(row._mapping) if row else None
                
            except Exception as e:
                self.log_error(
                    "Failed to get row by ID",
                    error=e,
                    table=table,
                    id=id_
                )
                raise
    
    async def close(self):
        """Close database connection."""
        try:
            if self.engine:
                await self.engine.dispose()
                self.log_info("PostgreSQL connection closed")
                
        except Exception as e:
            self.log_error("Failed to close PostgreSQL connection", error=e)
            raise

# Create singleton instance
pg_connector = PostgresConnector() 