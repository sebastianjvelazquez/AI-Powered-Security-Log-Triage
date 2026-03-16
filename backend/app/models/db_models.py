from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.enums import AuditActorType, EnrichmentStatus, IncidentStatus, IndicatorType


class Upload(Base):
    __tablename__ = "uploads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    total_lines: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    normalized_event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    detection_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    incident_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    normalized_events: Mapped[list["NormalizedEventRecord"]] = relationship(
        "NormalizedEventRecord", back_populates="upload", cascade="all, delete-orphan"
    )
    detections: Mapped[list["DetectionRecord"]] = relationship(
        "DetectionRecord", back_populates="upload", cascade="all, delete-orphan"
    )
    incidents: Mapped[list["Incident"]] = relationship("Incident", back_populates="upload", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="upload", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    asset_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    criticality: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    normalized_events: Mapped[list["NormalizedEventRecord"]] = relationship("NormalizedEventRecord", back_populates="asset")
    incidents: Mapped[list["Incident"]] = relationship("Incident", back_populates="asset")


class NormalizedEventRecord(Base):
    __tablename__ = "normalized_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    upload_id: Mapped[int] = mapped_column(Integer, ForeignKey("uploads.id", ondelete="CASCADE"), nullable=False)
    asset_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    event_index: Mapped[int] = mapped_column(Integer, nullable=False)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    timestamp_raw: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    upload: Mapped["Upload"] = relationship("Upload", back_populates="normalized_events")
    asset: Mapped["Asset | None"] = relationship("Asset", back_populates="normalized_events")
    detections: Mapped[list["DetectionRecord"]] = relationship(
        "DetectionRecord", back_populates="normalized_event", cascade="all, delete-orphan"
    )
    incident_links: Mapped[list["IncidentEventLink"]] = relationship(
        "IncidentEventLink", back_populates="normalized_event", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("upload_id", "event_index", name="uq_normalized_event_upload_index"),)


class DetectionRecord(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    upload_id: Mapped[int] = mapped_column(Integer, ForeignKey("uploads.id", ondelete="CASCADE"), nullable=False)
    normalized_event_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("normalized_events.id", ondelete="CASCADE"), nullable=False
    )
    rule_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_weight: Mapped[int] = mapped_column(Integer, nullable=False)
    detection_context: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    upload: Mapped["Upload"] = relationship("Upload", back_populates="detections")
    normalized_event: Mapped["NormalizedEventRecord"] = relationship("NormalizedEventRecord", back_populates="detections")
    incident_links: Mapped[list["IncidentEventLink"]] = relationship(
        "IncidentEventLink", back_populates="detection", cascade="all, delete-orphan"
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    upload_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("uploads.id", ondelete="SET NULL"), nullable=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=IncidentStatus.NEW.value, index=True)
    source_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    upload: Mapped["Upload | None"] = relationship("Upload", back_populates="incidents")
    asset: Mapped["Asset | None"] = relationship("Asset", back_populates="incidents")
    incident_events: Mapped[list["IncidentEventLink"]] = relationship(
        "IncidentEventLink", back_populates="incident", cascade="all, delete-orphan"
    )
    enrichments: Mapped[list["IncidentEnrichment"]] = relationship(
        "IncidentEnrichment", back_populates="incident", cascade="all, delete-orphan"
    )
    scores: Mapped[list["IncidentScore"]] = relationship(
        "IncidentScore", back_populates="incident", cascade="all, delete-orphan"
    )
    analyst_reviews: Mapped[list["AnalystReview"]] = relationship(
        "AnalystReview", back_populates="incident", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="incident", cascade="all, delete-orphan")


class IncidentEventLink(Base):
    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    normalized_event_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("normalized_events.id", ondelete="CASCADE"), nullable=False
    )
    detection_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("detections.id", ondelete="SET NULL"), nullable=True)
    link_type: Mapped[str] = mapped_column(String(32), nullable=False, default="evidence")
    linked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="incident_events")
    normalized_event: Mapped["NormalizedEventRecord"] = relationship("NormalizedEventRecord", back_populates="incident_links")
    detection: Mapped["DetectionRecord | None"] = relationship("DetectionRecord", back_populates="incident_links")

    __table_args__ = (
        UniqueConstraint("incident_id", "normalized_event_id", "detection_id", name="uq_incident_event_detection"),
    )


class IncidentEnrichment(Base):
    __tablename__ = "incident_enrichments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    enrichment_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=EnrichmentStatus.READY.value)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="enrichments")


class IncidentScore(Base):
    __tablename__ = "incident_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    total_score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    score_breakdown: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    scoring_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="scores")


class AnalystReview(Base):
    __tablename__ = "analyst_reviews"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    reviewer: Mapped[str] = mapped_column(String(128), nullable=False)
    disposition: Mapped[str] = mapped_column(String(64), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    override_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    override_mitre_techniques: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    override_recommended_actions: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="analyst_reviews")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True)
    upload_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("uploads.id", ondelete="CASCADE"), nullable=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False, default=AuditActorType.SYSTEM.value)
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    incident: Mapped["Incident | None"] = relationship("Incident", back_populates="audit_logs")
    upload: Mapped["Upload | None"] = relationship("Upload", back_populates="audit_logs")


class IOCache(Base):
    __tablename__ = "ioc_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    indicator: Mapped[str] = mapped_column(String(255), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False, default=IndicatorType.IP.value)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    reputation_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_malicious: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    attributes: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (UniqueConstraint("indicator", "indicator_type", "source", name="uq_ioc_cache_indicator"),)


Index("ix_detections_upload_rule", DetectionRecord.upload_id, DetectionRecord.rule_name)
Index("ix_incidents_upload_status", Incident.upload_id, Incident.status)
