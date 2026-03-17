"""security hardening schema

Revision ID: 20260317_0004
Revises: 20260316_0003
Create Date: 2026-03-17 09:30:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260317_0004"
down_revision = "20260316_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("uploads", sa.Column("sha256", sa.String(length=64), nullable=True))
    op.add_column("uploads", sa.Column("mime_type", sa.String(length=128), nullable=True))
    op.add_column("uploads", sa.Column("pii_redacted", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("uploads", sa.Column("retention_expires_at", sa.DateTime(), nullable=True))

    op.execute("UPDATE uploads SET sha256 = '' WHERE sha256 IS NULL")
    op.execute("UPDATE uploads SET mime_type = 'text/plain' WHERE mime_type IS NULL")

    op.alter_column("uploads", "sha256", existing_type=sa.String(length=64), nullable=False)
    op.alter_column("uploads", "mime_type", existing_type=sa.String(length=128), nullable=False)
    op.create_index("ix_uploads_sha256", "uploads", ["sha256"])
    op.create_index("ix_uploads_retention_expires_at", "uploads", ["retention_expires_at"])


def downgrade() -> None:
    op.drop_index("ix_uploads_retention_expires_at", table_name="uploads")
    op.drop_index("ix_uploads_sha256", table_name="uploads")
    op.drop_column("uploads", "retention_expires_at")
    op.drop_column("uploads", "pii_redacted")
    op.drop_column("uploads", "mime_type")
    op.drop_column("uploads", "sha256")
