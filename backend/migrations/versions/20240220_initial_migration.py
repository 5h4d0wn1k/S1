"""Initial migration

Revision ID: 20240220_initial
Revises: 
Create Date: 2024-02-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20240220_initial'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Create roles table
    op.create_table(
        'roles',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('description', sa.String(length=200), nullable=True),
        sa.Column('permissions', postgresql.JSON(), nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_roles')),
        sa.UniqueConstraint('name', name=op.f('uq_roles_name'))
    )
    op.create_index(op.f('ix_roles_created_at'), 'roles', ['created_at'], unique=False)
    op.create_index(op.f('ix_roles_name'), 'roles', ['name'], unique=True)
    op.create_index(op.f('ix_roles_updated_at'), 'roles', ['updated_at'], unique=False)

    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=100), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('is_superuser', sa.Boolean(), nullable=False),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False),
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.Column('password_changed_at', sa.DateTime(), nullable=False),
        sa.Column('require_password_change', sa.Boolean(), nullable=False),
        sa.Column('mfa_enabled', sa.Boolean(), nullable=False),
        sa.Column('mfa_secret', sa.String(length=32), nullable=True),
        sa.Column('preferences', postgresql.JSON(), nullable=False),
        sa.Column('api_key', sa.String(length=64), nullable=True),
        sa.Column('api_key_expires_at', sa.DateTime(), nullable=True),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], name=op.f('fk_users_role_id_roles')),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
        sa.UniqueConstraint('api_key', name=op.f('uq_users_api_key')),
        sa.UniqueConstraint('email', name=op.f('uq_users_email')),
        sa.UniqueConstraint('username', name=op.f('uq_users_username')),
        sa.UniqueConstraint('uuid', name=op.f('uq_users_uuid'))
    )
    op.create_index(op.f('ix_users_created_at'), 'users', ['created_at'], unique=False)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_updated_at'), 'users', ['updated_at'], unique=False)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_index(op.f('ix_users_uuid'), 'users', ['uuid'], unique=True)

    # Create playbooks table
    op.create_table(
        'playbooks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('type', sa.Enum('INCIDENT_RESPONSE', 'INVESTIGATION', 'CONTAINMENT', 'ERADICATION', 'RECOVERY', 'THREAT_HUNTING', name='playbooktype'), nullable=False),
        sa.Column('status', sa.Enum('DRAFT', 'ACTIVE', 'DEPRECATED', 'ARCHIVED', name='playbookstatus'), nullable=False),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('steps', postgresql.JSON(), nullable=False),
        sa.Column('automation', postgresql.JSON(), nullable=False),
        sa.Column('references', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('version', sa.String(length=20), nullable=False),
        sa.Column('author_id', sa.Integer(), nullable=False),
        sa.Column('published_at', sa.DateTime(), nullable=True),
        sa.Column('last_reviewed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['author_id'], ['users.id'], name=op.f('fk_playbooks_author_id_users')),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_playbooks')),
        sa.UniqueConstraint('uuid', name=op.f('uq_playbooks_uuid'))
    )
    op.create_index(op.f('ix_playbooks_created_at'), 'playbooks', ['created_at'], unique=False)
    op.create_index(op.f('ix_playbooks_updated_at'), 'playbooks', ['updated_at'], unique=False)
    op.create_index(op.f('ix_playbooks_uuid'), 'playbooks', ['uuid'], unique=True)

    # Create incidents table
    op.create_table(
        'incidents',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', name='incidentseverity'), nullable=False),
        sa.Column('status', sa.Enum('NEW', 'INVESTIGATING', 'CONTAINED', 'ERADICATED', 'RECOVERED', 'CLOSED', name='incidentstatus'), nullable=False),
        sa.Column('category', sa.Enum('MALWARE', 'PHISHING', 'DATA_BREACH', 'UNAUTHORIZED_ACCESS', 'DENIAL_OF_SERVICE', 'INSIDER_THREAT', 'OTHER', name='incidentcategory'), nullable=False),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('affected_systems', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('affected_users', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('business_impact', sa.Text(), nullable=True),
        sa.Column('data_breach', sa.Boolean(), nullable=False),
        sa.Column('detected_at', sa.DateTime(), nullable=False),
        sa.Column('contained_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('root_cause', sa.Text(), nullable=True),
        sa.Column('attack_vector', sa.String(length=200), nullable=True),
        sa.Column('indicators', postgresql.JSON(), nullable=False),
        sa.Column('timeline', postgresql.JSON(), nullable=False),
        sa.Column('mitre_tactics', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('mitre_techniques', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('playbook_id', sa.Integer(), nullable=True),
        sa.Column('containment_strategy', sa.Text(), nullable=True),
        sa.Column('eradication_steps', sa.Text(), nullable=True),
        sa.Column('recovery_steps', sa.Text(), nullable=True),
        sa.Column('lessons_learned', sa.Text(), nullable=True),
        sa.Column('lead_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['lead_id'], ['users.id'], name=op.f('fk_incidents_lead_id_users')),
        sa.ForeignKeyConstraint(['playbook_id'], ['playbooks.id'], name=op.f('fk_incidents_playbook_id_playbooks')),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_incidents')),
        sa.UniqueConstraint('uuid', name=op.f('uq_incidents_uuid'))
    )
    op.create_index(op.f('ix_incidents_created_at'), 'incidents', ['created_at'], unique=False)
    op.create_index(op.f('ix_incidents_detected_at'), 'incidents', ['detected_at'], unique=False)
    op.create_index(op.f('ix_incidents_updated_at'), 'incidents', ['updated_at'], unique=False)
    op.create_index(op.f('ix_incidents_uuid'), 'incidents', ['uuid'], unique=True)

    # Create alerts table
    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', name='alertseverity'), nullable=False),
        sa.Column('status', sa.Enum('NEW', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE', 'IGNORED', name='alertstatus'), nullable=False),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('source_id', sa.String(length=100), nullable=True),
        sa.Column('host', sa.String(length=255), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user', sa.String(length=100), nullable=True),
        sa.Column('process', sa.String(length=200), nullable=True),
        sa.Column('mitre_tactics', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('mitre_techniques', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('enrichment', postgresql.JSON(), nullable=False),
        sa.Column('threat_intel', postgresql.JSON(), nullable=False),
        sa.Column('ai_analysis', postgresql.JSON(), nullable=True),
        sa.Column('false_positive_reason', sa.Text(), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),
        sa.Column('detected_at', sa.DateTime(), nullable=False),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('raw_data', postgresql.JSON(), nullable=False),
        sa.Column('assigned_to_id', sa.Integer(), nullable=True),
        sa.Column('incident_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['assigned_to_id'], ['users.id'], name=op.f('fk_alerts_assigned_to_id_users')),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_alerts_incident_id_incidents')),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_alerts')),
        sa.UniqueConstraint('uuid', name=op.f('uq_alerts_uuid'))
    )
    op.create_index(op.f('ix_alerts_created_at'), 'alerts', ['created_at'], unique=False)
    op.create_index(op.f('ix_alerts_detected_at'), 'alerts', ['detected_at'], unique=False)
    op.create_index(op.f('ix_alerts_updated_at'), 'alerts', ['updated_at'], unique=False)
    op.create_index(op.f('ix_alerts_uuid'), 'alerts', ['uuid'], unique=True)

    # Create incident_assignments table
    op.create_table(
        'incident_assignments',
        sa.Column('incident_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_incident_assignments_incident_id_incidents')),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_incident_assignments_user_id_users')),
        sa.PrimaryKeyConstraint('incident_id', 'user_id', name=op.f('pk_incident_assignments'))
    )

def downgrade() -> None:
    op.drop_table('incident_assignments')
    op.drop_table('alerts')
    op.drop_table('incidents')
    op.drop_table('playbooks')
    op.drop_table('users')
    op.drop_table('roles') 