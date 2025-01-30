from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import String, JSON, ForeignKey, Enum, Text, Table, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, ARRAY

from .base import Base

# Many-to-many relationship table for incident-user assignments
incident_assignments = Table(
    'incident_assignments',
    Base.metadata,
    Column('incident_id', ForeignKey('incidents.id'), primary_key=True),
    Column('user_id', ForeignKey('users.id'), primary_key=True)
)

class IncidentSeverity(str, Enum):
    """Incident severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class IncidentStatus(str, Enum):
    """Incident status types."""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"

class IncidentCategory(str, Enum):
    """Incident category types."""
    MALWARE = "malware"
    PHISHING = "phishing"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DENIAL_OF_SERVICE = "denial_of_service"
    INSIDER_THREAT = "insider_threat"
    OTHER = "other"

class Incident(Base):
    """Incident model."""
    
    # Basic info
    uuid: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        default=uuid4,
        unique=True,
        index=True
    )
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    
    # Classification
    severity: Mapped[IncidentSeverity] = mapped_column(default=IncidentSeverity.MEDIUM)
    status: Mapped[IncidentStatus] = mapped_column(default=IncidentStatus.NEW)
    category: Mapped[IncidentCategory] = mapped_column()
    tags: Mapped[List[str]] = mapped_column(ARRAY(String))
    
    # Impact
    affected_systems: Mapped[List[str]] = mapped_column(ARRAY(String))
    affected_users: Mapped[List[str]] = mapped_column(ARRAY(String))
    business_impact: Mapped[Optional[str]] = mapped_column(Text)
    data_breach: Mapped[bool] = mapped_column(default=False)
    
    # Timeline
    detected_at: Mapped[datetime] = mapped_column(index=True)
    contained_at: Mapped[Optional[datetime]] = mapped_column()
    resolved_at: Mapped[Optional[datetime]] = mapped_column()
    
    # Analysis
    root_cause: Mapped[Optional[str]] = mapped_column(Text)
    attack_vector: Mapped[Optional[str]] = mapped_column(String(200))
    indicators: Mapped[dict] = mapped_column(JSON, default=dict)
    timeline: Mapped[dict] = mapped_column(JSON, default=list)
    
    # MITRE ATT&CK
    mitre_tactics: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    mitre_techniques: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    
    # Response
    playbook_id: Mapped[Optional[int]] = mapped_column(ForeignKey("playbooks.id"))
    playbook: Mapped[Optional["Playbook"]] = relationship()
    
    containment_strategy: Mapped[Optional[str]] = mapped_column(Text)
    eradication_steps: Mapped[Optional[str]] = mapped_column(Text)
    recovery_steps: Mapped[Optional[str]] = mapped_column(Text)
    lessons_learned: Mapped[Optional[str]] = mapped_column(Text)
    
    # Relationships
    alerts: Mapped[List["Alert"]] = relationship(back_populates="incident")
    assigned_users: Mapped[List["User"]] = relationship(
        secondary=incident_assignments,
        backref="assigned_incidents"
    )
    
    lead_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"))
    lead: Mapped[Optional["User"]] = relationship(foreign_keys=[lead_id])
    
    def assign_lead(self, user: "User") -> None:
        """Assign incident lead."""
        self.lead = user
        if user not in self.assigned_users:
            self.assigned_users.append(user)
    
    def add_team_member(self, user: "User") -> None:
        """Add team member to incident."""
        if user not in self.assigned_users:
            self.assigned_users.append(user)
    
    def remove_team_member(self, user: "User") -> None:
        """Remove team member from incident."""
        if user in self.assigned_users:
            self.assigned_users.remove(user)
    
    def update_status(self, status: IncidentStatus, notes: Optional[str] = None) -> None:
        """Update incident status."""
        self.status = status
        if status == IncidentStatus.CONTAINED:
            self.contained_at = datetime.utcnow()
        elif status == IncidentStatus.CLOSED:
            self.resolved_at = datetime.utcnow()
        
        if notes:
            self.timeline.append({
                "timestamp": datetime.utcnow().isoformat(),
                "type": "status_change",
                "status": status,
                "notes": notes
            })
    
    def add_timeline_event(
        self,
        event_type: str,
        description: str,
        metadata: Optional[dict] = None
    ) -> None:
        """Add event to incident timeline."""
        self.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "description": description,
            **(metadata or {})
        })
    
    def add_indicator(self, indicator_type: str, value: str, metadata: Optional[dict] = None) -> None:
        """Add indicator of compromise."""
        if indicator_type not in self.indicators:
            self.indicators[indicator_type] = []
        
        self.indicators[indicator_type].append({
            "value": value,
            "added_at": datetime.utcnow().isoformat(),
            **(metadata or {})
        }) 