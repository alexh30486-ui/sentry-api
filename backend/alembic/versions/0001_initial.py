"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-07-28

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    scan_status = postgresql.ENUM(
        "pending", "running", "completed", "failed", name="scan_status"
    )
    scan_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "owner_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target_base_url", sa.String(2048), nullable=False),
        sa.Column(
            "status",
            sa.Enum("pending", "running", "completed", "failed", name="scan_status"),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("modules", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("config", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.String(2048), nullable=True),
    )
    op.create_index("ix_scans_owner_id", "scans", ["owner_id"])

    severity = postgresql.ENUM(
        "info", "low", "medium", "high", "critical", name="severity"
    )
    severity.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("module", sa.String(64), nullable=False),
        sa.Column("owasp_category", sa.String(16), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column(
            "severity",
            sa.Enum("info", "low", "medium", "high", "critical", name="severity"),
            nullable=False,
        ),
        sa.Column("endpoint", sa.String(2048), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
    op.execute("DROP TYPE IF EXISTS severity")

    op.drop_index("ix_scans_owner_id", table_name="scans")
    op.drop_table("scans")
    op.execute("DROP TYPE IF EXISTS scan_status")

    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
