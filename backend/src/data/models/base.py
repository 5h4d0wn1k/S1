from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

from sqlalchemy import MetaData
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from pydantic import BaseModel, Field, ConfigDict

# Naming convention for constraints
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

class Base(DeclarativeBase):
    """Base model class."""
    
    metadata = MetaData(naming_convention=convention)
    
    # Common columns
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        index=True
    )
    
    # Use table name as lowercase plural of class name
    @declared_attr.directive
    def __tablename__(cls) -> str:
        return cls.__name__.lower() + 's'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
        }
    
    def update(self, **kwargs: Any) -> None:
        """Update model attributes."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

class BaseModelWithTimestamps(BaseModel):
    """Base model with timestamp fields."""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = ConfigDict(from_attributes=True)

class BaseModelWithID(BaseModelWithTimestamps):
    """Base model with ID and timestamp fields."""
    id: int = Field(default=None)
    uuid: UUID = Field(default_factory=uuid4)

class BaseModelWithMetadata(BaseModelWithID):
    """Base model with metadata fields."""
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    metadata: dict = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    description: Optional[str] = None
    enabled: bool = True 