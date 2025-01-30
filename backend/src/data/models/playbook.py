from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import String, JSON, ForeignKey, Enum, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, ARRAY

from .base import Base

class PlaybookType(str, Enum):
    """Playbook types."""
    INCIDENT_RESPONSE = "incident_response"
    INVESTIGATION = "investigation"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    THREAT_HUNTING = "threat_hunting"

class PlaybookStatus(str, Enum):
    """Playbook status types."""
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"

class Playbook(Base):
    """Playbook model."""
    
    # Basic info
    uuid: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        default=uuid4,
        unique=True,
        index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    
    # Classification
    type: Mapped[PlaybookType] = mapped_column()
    status: Mapped[PlaybookStatus] = mapped_column(default=PlaybookStatus.DRAFT)
    tags: Mapped[List[str]] = mapped_column(ARRAY(String))
    
    # Content
    steps: Mapped[List[dict]] = mapped_column(JSON)  # List of playbook steps
    automation: Mapped[dict] = mapped_column(JSON, default=dict)  # Automation rules
    references: Mapped[List[str]] = mapped_column(ARRAY(String))
    
    # Metadata
    version: Mapped[str] = mapped_column(String(20))
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    author: Mapped["User"] = relationship()
    
    # Timestamps
    published_at: Mapped[Optional[datetime]] = mapped_column()
    last_reviewed_at: Mapped[Optional[datetime]] = mapped_column()
    
    # Relationships
    incidents: Mapped[List["Incident"]] = relationship(back_populates="playbook")
    
    def publish(self, version: Optional[str] = None) -> None:
        """Publish playbook."""
        self.status = PlaybookStatus.ACTIVE
        self.published_at = datetime.utcnow()
        if version:
            self.version = version
    
    def deprecate(self, reason: Optional[str] = None) -> None:
        """Deprecate playbook."""
        self.status = PlaybookStatus.DEPRECATED
        if reason:
            self.steps.append({
                "type": "deprecation_notice",
                "timestamp": datetime.utcnow().isoformat(),
                "reason": reason
            })
    
    def archive(self) -> None:
        """Archive playbook."""
        self.status = PlaybookStatus.ARCHIVED
    
    def add_step(
        self,
        title: str,
        description: str,
        step_type: str,
        automation: Optional[dict] = None,
        metadata: Optional[dict] = None
    ) -> None:
        """Add step to playbook."""
        step = {
            "id": len(self.steps) + 1,
            "title": title,
            "description": description,
            "type": step_type,
            "added_at": datetime.utcnow().isoformat()
        }
        
        if automation:
            step["automation"] = automation
        if metadata:
            step.update(metadata)
        
        self.steps.append(step)
    
    def update_step(self, step_id: int, **kwargs: Any) -> None:
        """Update playbook step."""
        for step in self.steps:
            if step["id"] == step_id:
                step.update(kwargs)
                step["updated_at"] = datetime.utcnow().isoformat()
                break
    
    def remove_step(self, step_id: int) -> None:
        """Remove step from playbook."""
        self.steps = [step for step in self.steps if step["id"] != step_id]
    
    def add_automation(self, rule_name: str, rule_config: dict) -> None:
        """Add automation rule."""
        self.automation[rule_name] = {
            "config": rule_config,
            "added_at": datetime.utcnow().isoformat()
        }
    
    def remove_automation(self, rule_name: str) -> None:
        """Remove automation rule."""
        self.automation.pop(rule_name, None) 