"""correlation engine schema

Revision ID: 20260316_0003
Revises: 20260316_0002
Create Date: 2026-03-16 01:15:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260316_0003"
down_revision = "20260316_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("normalized_events", sa.Column("hostname", sa.String(length=255), nullable=True))
    op.create_index("ix_normalized_events_hostname", "normalized_events", ["hostname"])

    op.add_column("incidents", sa.Column("correlation_summary", sa.Text(), nullable=True))
    op.add_column("incidents", sa.Column("correlation_context", sa.JSON(), nullable=True))

    op.create_table(
        "incident_uploads",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("upload_id", sa.Integer(), nullable=False),
        sa.Column("relation_type", sa.String(length=32), nullable=False),
        sa.Column("linked_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["upload_id"], ["uploads.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "upload_id", name="uq_incident_upload_link"),
    )
    op.create_index("ix_incident_uploads_id", "incident_uploads", ["id"])


def downgrade() -> None:
    op.drop_index("ix_incident_uploads_id", table_name="incident_uploads")
    op.drop_table("incident_uploads")
    op.drop_column("incidents", "correlation_context")
    op.drop_column("incidents", "correlation_summary")
    op.drop_index("ix_normalized_events_hostname", table_name="normalized_events")
    op.drop_column("normalized_events", "hostname")
