"""async processing jobs

Revision ID: 20260316_0002
Revises: 20260316_0001
Create Date: 2026-03-16 00:30:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260316_0002"
down_revision = "20260316_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("uploads", sa.Column("storage_path", sa.String(length=512), nullable=True))
    op.add_column("uploads", sa.Column("processing_status", sa.String(length=32), nullable=False, server_default="completed"))
    op.add_column("uploads", sa.Column("last_error", sa.Text(), nullable=True))
    op.create_index("ix_uploads_processing_status", "uploads", ["processing_status"])

    op.create_table(
        "processing_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("upload_id", sa.Integer(), nullable=False),
        sa.Column("celery_task_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("current_stage", sa.String(length=32), nullable=False),
        sa.Column("stage_history", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["upload_id"], ["uploads.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("celery_task_id"),
        sa.UniqueConstraint("job_id"),
    )
    op.create_index("ix_processing_jobs_created_at", "processing_jobs", ["created_at"])
    op.create_index("ix_processing_jobs_current_stage", "processing_jobs", ["current_stage"])
    op.create_index("ix_processing_jobs_id", "processing_jobs", ["id"])
    op.create_index("ix_processing_jobs_job_id", "processing_jobs", ["job_id"])
    op.create_index("ix_processing_jobs_status", "processing_jobs", ["status"])
    op.create_index("ix_processing_jobs_upload_id", "processing_jobs", ["upload_id"])


def downgrade() -> None:
    op.drop_index("ix_processing_jobs_upload_id", table_name="processing_jobs")
    op.drop_index("ix_processing_jobs_status", table_name="processing_jobs")
    op.drop_index("ix_processing_jobs_job_id", table_name="processing_jobs")
    op.drop_index("ix_processing_jobs_id", table_name="processing_jobs")
    op.drop_index("ix_processing_jobs_current_stage", table_name="processing_jobs")
    op.drop_index("ix_processing_jobs_created_at", table_name="processing_jobs")
    op.drop_table("processing_jobs")
    op.drop_index("ix_uploads_processing_status", table_name="uploads")
    op.drop_column("uploads", "last_error")
    op.drop_column("uploads", "processing_status")
    op.drop_column("uploads", "storage_path")
