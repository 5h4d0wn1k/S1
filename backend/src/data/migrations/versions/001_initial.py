"""Initial migration

Revision ID: 001
Revises: 
Create Date: 2024-03-20 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Create enum types
    op.execute("CREATE TYPE user_role AS ENUM ('admin', 'security_analyst', 'asset_manager', 'viewer')")
    op.execute("CREATE TYPE alert_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info')")
    op.execute("CREATE TYPE alert_status AS ENUM ('new', 'in_progress', 'resolved', 'false_positive')")
    op.execute("CREATE TYPE scan_type AS ENUM ('vulnerability', 'compliance', 'penetration', 'configuration')")
    op.execute("CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled')")
    
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=False),
        sa.Column('role', sa.Enum('admin', 'security_analyst', 'asset_manager', 'viewer', name='user_role'), nullable=False),
        sa.Column('organization', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )
    
    # Create assets table
    op.create_table(
        'assets',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('ip_address', postgresql.INET, nullable=True),
        sa.Column('type', sa.String(length=50), nullable=False),
        sa.Column('owner', sa.String(length=255), nullable=False),
        sa.Column('criticality', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='RESTRICT'),
        sa.UniqueConstraint('hostname')
    )
    
    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('type', sa.Enum('vulnerability', 'compliance', 'penetration', 'configuration', name='scan_type'), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('configuration', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('status', sa.Enum('pending', 'running', 'completed', 'failed', 'cancelled', name='scan_status'), nullable=False),
        sa.Column('findings', postgresql.JSONB, nullable=True),
        sa.Column('notes', sa.Text, nullable=True),
        sa.Column('schedule', sa.String(length=100), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['target_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='RESTRICT')
    )
    
    # Create alerts table
    op.create_table(
        'alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text, nullable=False),
        sa.Column('severity', sa.Enum('critical', 'high', 'medium', 'low', 'info', name='alert_severity'), nullable=False),
        sa.Column('status', sa.Enum('new', 'in_progress', 'resolved', 'false_positive', name='alert_status'), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('source_id', sa.String(length=255), nullable=True),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('assignee', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('context', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('tags', postgresql.ARRAY(sa.String), nullable=False, server_default='{}'),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['assignee'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ondelete='SET NULL')
    )
    
    # Create indexes
    op.create_index('ix_users_email', 'users', ['email'])
    op.create_index('ix_users_role', 'users', ['role'])
    op.create_index('ix_assets_type', 'assets', ['type'])
    op.create_index('ix_assets_owner', 'assets', ['owner'])
    op.create_index('ix_assets_criticality', 'assets', ['criticality'])
    op.create_index('ix_scans_type', 'scans', ['type'])
    op.create_index('ix_scans_status', 'scans', ['status'])
    op.create_index('ix_scans_target_id', 'scans', ['target_id'])
    op.create_index('ix_alerts_severity', 'alerts', ['severity'])
    op.create_index('ix_alerts_status', 'alerts', ['status'])
    op.create_index('ix_alerts_source', 'alerts', ['source'])
    op.create_index('ix_alerts_asset_id', 'alerts', ['asset_id'])
    op.create_index('ix_alerts_scan_id', 'alerts', ['scan_id'])
    op.create_index('ix_alerts_assignee', 'alerts', ['assignee'])
    op.create_index('ix_alerts_created_at', 'alerts', ['created_at'])
    
    # Create GiST index for IP address range queries
    op.execute('CREATE INDEX ix_assets_ip_address ON assets USING gist (ip_address inet_ops)')
    
    # Create triggers for updated_at
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = now();
            RETURN NEW;
        END;
        $$ language 'plpgsql';
    """)
    
    for table in ['users', 'assets', 'scans', 'alerts']:
        op.execute(f"""
            CREATE TRIGGER update_updated_at
                BEFORE UPDATE ON {table}
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column();
        """)

def downgrade() -> None:
    # Drop triggers
    for table in ['users', 'assets', 'scans', 'alerts']:
        op.execute(f"DROP TRIGGER IF EXISTS update_updated_at ON {table}")
    
    # Drop function
    op.execute("DROP FUNCTION IF EXISTS update_updated_at_column")
    
    # Drop tables
    op.drop_table('alerts')
    op.drop_table('scans')
    op.drop_table('assets')
    op.drop_table('users')
    
    # Drop enum types
    op.execute("DROP TYPE IF EXISTS user_role")
    op.execute("DROP TYPE IF EXISTS alert_severity")
    op.execute("DROP TYPE IF EXISTS alert_status")
    op.execute("DROP TYPE IF EXISTS scan_type")
    op.execute("DROP TYPE IF EXISTS scan_status") 