from typing import Any, Dict, Generic, List, Optional, Type, TypeVar
from uuid import UUID

from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.base import Base

ModelType = TypeVar("ModelType", bound=Base)
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)

class BaseRepository(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    """Base repository with common CRUD operations."""
    
    def __init__(self, model: Type[ModelType]):
        """Initialize repository with model."""
        self.model = model
    
    async def get(
        self,
        session: AsyncSession,
        id: Any
    ) -> Optional[ModelType]:
        """Get record by ID."""
        result = await session.execute(
            select(self.model).where(self.model.id == id)
        )
        return result.scalar_one_or_none()
    
    async def get_by_uuid(
        self,
        session: AsyncSession,
        uuid: UUID
    ) -> Optional[ModelType]:
        """Get record by UUID."""
        result = await session.execute(
            select(self.model).where(self.model.uuid == uuid)
        )
        return result.scalar_one_or_none()
    
    async def get_all(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[ModelType]:
        """Get all records with pagination."""
        result = await session.execute(
            select(self.model)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def create(
        self,
        session: AsyncSession,
        obj_in: CreateSchemaType
    ) -> ModelType:
        """Create new record."""
        obj_in_data = jsonable_encoder(obj_in)
        db_obj = self.model(**obj_in_data)
        session.add(db_obj)
        await session.flush()
        await session.refresh(db_obj)
        return db_obj
    
    async def update(
        self,
        session: AsyncSession,
        *,
        db_obj: ModelType,
        obj_in: UpdateSchemaType | Dict[str, Any]
    ) -> ModelType:
        """Update record."""
        obj_data = jsonable_encoder(db_obj)
        
        if isinstance(obj_in, dict):
            update_data = obj_in
        else:
            update_data = obj_in.model_dump(exclude_unset=True)
            
        for field in obj_data:
            if field in update_data:
                setattr(db_obj, field, update_data[field])
                
        session.add(db_obj)
        await session.flush()
        await session.refresh(db_obj)
        return db_obj
    
    async def delete(
        self,
        session: AsyncSession,
        *,
        id: Any
    ) -> bool:
        """Delete record by ID."""
        obj = await self.get(session, id)
        if obj:
            await session.delete(obj)
            await session.flush()
            return True
        return False
    
    async def count(
        self,
        session: AsyncSession
    ) -> int:
        """Get total count of records."""
        result = await session.execute(
            select(self.model.id)
        )
        return len(result.scalars().all())
    
    async def exists(
        self,
        session: AsyncSession,
        id: Any
    ) -> bool:
        """Check if record exists by ID."""
        result = await session.execute(
            select(self.model.id).where(self.model.id == id)
        )
        return result.scalar_one_or_none() is not None
    
    async def exists_by_uuid(
        self,
        session: AsyncSession,
        uuid: UUID
    ) -> bool:
        """Check if record exists by UUID."""
        result = await session.execute(
            select(self.model.id).where(self.model.uuid == uuid)
        )
        return result.scalar_one_or_none() is not None 