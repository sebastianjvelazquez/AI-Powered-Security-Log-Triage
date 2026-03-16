"""incident centric schema

Revision ID: 20260316_0001
Revises: None
Create Date: 2026-03-16 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260316_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "uploads",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("total_lines", sa.Integer(), nullable=False),
        sa.Column("normalized_event_count", sa.Integer(), nullable=False),
        sa.Column("detection_count", sa.Integer(), nullable=False),
        sa.Column("incident_count", sa.Integer(), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_uploads_id", "uploads", ["id"])
    op.create_index("ix_uploads_source_type", "uploads", ["source_type"])
    op.create_index("ix_uploads_uploaded_at", "uploads", ["uploaded_at"])

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("asset_key", sa.String(length=255), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("criticality", sa.Float(), nullable=False),
        sa.Column("environment", sa.String(length=64), nullable=True),
        sa.Column("owner", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_key"),
    )
    op.create_index("ix_assets_id", "assets", ["id"])
    op.create_index("ix_assets_ip_address", "assets", ["ip_address"])

    op.create_table(
        "ioc_cache",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("indicator", sa.String(length=255), nullable=False),
        sa.Column("indicator_type", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("reputation_score", sa.Float(), nullable=True),
        sa.Column("is_malicious", sa.Boolean(), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("indicator", "indicator_type", "source", name="uq_ioc_cache_indicator"),
    )
    op.create_index("ix_ioc_cache_id", "ioc_cache", ["id"])

    op.create_table(
        "normalized_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("upload_id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=True),
        sa.Column("event_index", sa.Integer(), nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("observed_at", sa.DateTime(), nullable=True),
        sa.Column("timestamp_raw", sa.String(length=64), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("destination_ip", sa.String(length=64), nullable=True),
        sa.Column("user", sa.String(length=128), nullable=True),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=True),
        sa.Column("raw_message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["upload_id"], ["uploads.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("upload_id", "event_index", name="uq_normalized_event_upload_index"),
    )
    op.create_index("ix_normalized_events_destination_ip", "normalized_events", ["destination_ip"])
    op.create_index("ix_normalized_events_event_type", "normalized_events", ["event_type"])
    op.create_index("ix_normalized_events_id", "normalized_events", ["id"])
    op.create_index("ix_normalized_events_observed_at", "normalized_events", ["observed_at"])
    op.create_index("ix_normalized_events_source_ip", "normalized_events", ["source_ip"])
    op.create_index("ix_normalized_events_user", "normalized_events", ["user"])

    op.create_table(
        "detections",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("upload_id", sa.Integer(), nullable=False),
        sa.Column("normalized_event_id", sa.Integer(), nullable=False),
        sa.Column("rule_name", sa.String(length=128), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("risk_weight", sa.Integer(), nullable=False),
        sa.Column("detection_context", sa.JSON(), nullable=True),
        sa.Column("detected_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["normalized_event_id"], ["normalized_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["upload_id"], ["uploads.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_detections_detected_at", "detections", ["detected_at"])
    op.create_index("ix_detections_id", "detections", ["id"])
    op.create_index("ix_detections_rule_name", "detections", ["rule_name"])
    op.create_index("ix_detections_upload_rule", "detections", ["upload_id", "rule_name"])

    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("upload_id", sa.Integer(), nullable=True),
        sa.Column("asset_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("source_types", sa.JSON(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["upload_id"], ["uploads.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incidents_created_at", "incidents", ["created_at"])
    op.create_index("ix_incidents_first_seen_at", "incidents", ["first_seen_at"])
    op.create_index("ix_incidents_id", "incidents", ["id"])
    op.create_index("ix_incidents_last_seen_at", "incidents", ["last_seen_at"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_upload_status", "incidents", ["upload_id", "status"])

    op.create_table(
        "incident_enrichments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("enrichment_type", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incident_enrichments_enrichment_type", "incident_enrichments", ["enrichment_type"])
    op.create_index("ix_incident_enrichments_id", "incident_enrichments", ["id"])

    op.create_table(
        "incident_scores",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("total_score", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("score_breakdown", sa.JSON(), nullable=False),
        sa.Column("scoring_version", sa.String(length=32), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incident_scores_id", "incident_scores", ["id"])
    op.create_index("ix_incident_scores_incident_id", "incident_scores", ["incident_id"])

    op.create_table(
        "analyst_reviews",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("reviewer", sa.String(length=128), nullable=False),
        sa.Column("disposition", sa.String(length=64), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("override_severity", sa.String(length=16), nullable=True),
        sa.Column("override_mitre_techniques", sa.JSON(), nullable=True),
        sa.Column("override_recommended_actions", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analyst_reviews_id", "analyst_reviews", ["id"])
    op.create_index("ix_analyst_reviews_incident_id", "analyst_reviews", ["incident_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=True),
        sa.Column("upload_id", sa.Integer(), nullable=True),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("actor_type", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["upload_id"], ["uploads.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_id", "audit_logs", ["id"])

    op.create_table(
        "incident_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("normalized_event_id", sa.Integer(), nullable=False),
        sa.Column("detection_id", sa.Integer(), nullable=True),
        sa.Column("link_type", sa.String(length=32), nullable=False),
        sa.Column("linked_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["detection_id"], ["detections.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["normalized_event_id"], ["normalized_events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "normalized_event_id", "detection_id", name="uq_incident_event_detection"),
    )
    op.create_index("ix_incident_events_id", "incident_events", ["id"])

    op.execute("DROP TABLE IF EXISTS ai_analyses")
    op.execute("DROP TABLE IF EXISTS suspicious_events")
    op.execute("DROP TABLE IF EXISTS log_uploads")


def downgrade() -> None:
    op.create_table(
        "log_uploads",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("total_lines", sa.Integer(), nullable=False),
        sa.Column("suspicious_count", sa.Integer(), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "suspicious_events",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("upload_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.String(length=64), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("destination_ip", sa.String(length=64), nullable=True),
        sa.Column("user", sa.String(length=128), nullable=True),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=True),
        sa.Column("rule_name", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("risk_weight", sa.Integer(), nullable=False),
        sa.Column("raw_message", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["upload_id"], ["log_uploads.id"], ondelete="CASCADE"),
    )
    op.create_table(
        "ai_analyses",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("upload_id", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("attack_type", sa.String(length=128), nullable=False),
        sa.Column("mitre_techniques", sa.Text(), nullable=False),
        sa.Column("confidence_score", sa.Integer(), nullable=False),
        sa.Column("analysis_summary", sa.Text(), nullable=False),
        sa.Column("recommended_actions", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["upload_id"], ["log_uploads.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("upload_id"),
    )

    op.drop_index("ix_incident_events_id", table_name="incident_events")
    op.drop_table("incident_events")
    op.drop_index("ix_audit_logs_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_analyst_reviews_incident_id", table_name="analyst_reviews")
    op.drop_index("ix_analyst_reviews_id", table_name="analyst_reviews")
    op.drop_table("analyst_reviews")
    op.drop_index("ix_incident_scores_incident_id", table_name="incident_scores")
    op.drop_index("ix_incident_scores_id", table_name="incident_scores")
    op.drop_table("incident_scores")
    op.drop_index("ix_incident_enrichments_id", table_name="incident_enrichments")
    op.drop_index("ix_incident_enrichments_enrichment_type", table_name="incident_enrichments")
    op.drop_table("incident_enrichments")
    op.drop_index("ix_incidents_upload_status", table_name="incidents")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_index("ix_incidents_severity", table_name="incidents")
    op.drop_index("ix_incidents_last_seen_at", table_name="incidents")
    op.drop_index("ix_incidents_id", table_name="incidents")
    op.drop_index("ix_incidents_first_seen_at", table_name="incidents")
    op.drop_index("ix_incidents_created_at", table_name="incidents")
    op.drop_table("incidents")
    op.drop_index("ix_detections_upload_rule", table_name="detections")
    op.drop_index("ix_detections_rule_name", table_name="detections")
    op.drop_index("ix_detections_id", table_name="detections")
    op.drop_index("ix_detections_detected_at", table_name="detections")
    op.drop_table("detections")
    op.drop_index("ix_normalized_events_user", table_name="normalized_events")
    op.drop_index("ix_normalized_events_source_ip", table_name="normalized_events")
    op.drop_index("ix_normalized_events_observed_at", table_name="normalized_events")
    op.drop_index("ix_normalized_events_id", table_name="normalized_events")
    op.drop_index("ix_normalized_events_event_type", table_name="normalized_events")
    op.drop_index("ix_normalized_events_destination_ip", table_name="normalized_events")
    op.drop_table("normalized_events")
    op.drop_index("ix_ioc_cache_id", table_name="ioc_cache")
    op.drop_table("ioc_cache")
    op.drop_index("ix_assets_ip_address", table_name="assets")
    op.drop_index("ix_assets_id", table_name="assets")
    op.drop_table("assets")
    op.drop_index("ix_uploads_uploaded_at", table_name="uploads")
    op.drop_index("ix_uploads_source_type", table_name="uploads")
    op.drop_index("ix_uploads_id", table_name="uploads")
    op.drop_table("uploads")
