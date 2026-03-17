from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models.db_models import (
    Asset,
    AuditLog,
    DetectionRecord,
    Incident,
    IncidentEnrichment,
    IncidentEventLink,
    IncidentUploadLink,
    IncidentScore,
    IOCache,
    NormalizedEventRecord,
    Upload,
)
from app.models.enums import AuditActorType, IndicatorType
from app.models.schemas import DetectionCandidate, IncidentScoreView, LLMAnalysisOutput, NormalizedEvent
from app.utils.time_utils import parse_event_timestamp


class IncidentRepository:
    def create_upload(
        self,
        db: Session,
        *,
        filename: str,
        source_type: str,
        total_lines: int,
        normalized_event_count: int,
        storage_path: str | None = None,
        processing_status: str = "completed",
    ) -> Upload:
        upload = Upload(
            filename=filename,
            source_type=source_type,
            storage_path=storage_path,
            processing_status=processing_status,
            total_lines=total_lines,
            normalized_event_count=normalized_event_count,
        )
        db.add(upload)
        db.flush()
        return upload

    def get_or_create_asset(self, db: Session, *, ip_address: str | None) -> Asset | None:
        if not ip_address:
            return None

        stmt = select(Asset).where(Asset.asset_key == ip_address)
        existing = db.scalar(stmt)
        if existing is not None:
            return existing

        asset = Asset(asset_key=ip_address, ip_address=ip_address)
        db.add(asset)
        db.flush()
        return asset

    def create_normalized_events(
        self, db: Session, *, upload: Upload, normalized_events: list[NormalizedEvent]
    ) -> list[NormalizedEventRecord]:
        records: list[NormalizedEventRecord] = []
        for event_index, event in enumerate(normalized_events):
            asset = self.get_or_create_asset(db, ip_address=event.destination_ip)
            record = NormalizedEventRecord(
                upload_id=upload.id,
                asset_id=asset.id if asset else None,
                event_index=event_index,
                line_number=event.line_number,
                observed_at=parse_event_timestamp(event.timestamp),
                timestamp_raw=event.timestamp,
                hostname=event.hostname,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                user=event.user,
                event_type=event.event_type,
                status=event.status,
                raw_message=event.raw_message,
            )
            db.add(record)
            records.append(record)

        db.flush()
        return records

    def create_detections(
        self,
        db: Session,
        *,
        upload: Upload,
        normalized_event_records: list[NormalizedEventRecord],
        detection_candidates: list[DetectionCandidate],
    ) -> list[DetectionRecord]:
        records: list[DetectionRecord] = []
        for candidate in detection_candidates:
            normalized_event = normalized_event_records[candidate.normalized_event_index]
            record = DetectionRecord(
                upload_id=upload.id,
                normalized_event_id=normalized_event.id,
                rule_name=candidate.rule_name,
                reason=candidate.reason,
                risk_weight=candidate.risk_weight,
                detection_context={
                    "source_ip": candidate.source_ip,
                    "destination_ip": candidate.destination_ip,
                    "user": candidate.user,
                    "status": candidate.status,
                },
            )
            db.add(record)
            records.append(record)

        upload.detection_count = len(records)
        db.flush()
        return records

    def create_incident(
        self,
        db: Session,
        *,
        upload: Upload,
        asset: Asset | None,
        title: str,
        severity: str,
        risk_score: float,
        summary: str,
        source_types: list[str],
        first_seen_at: datetime | None,
        last_seen_at: datetime | None,
        correlation_summary: str | None = None,
        correlation_context: dict[str, object] | None = None,
    ) -> Incident:
        incident = Incident(
            upload_id=upload.id,
            asset_id=asset.id if asset else None,
            title=title,
            severity=severity,
            risk_score=risk_score,
            summary=summary,
            correlation_summary=correlation_summary,
            correlation_context=correlation_context,
            source_types=source_types,
            first_seen_at=first_seen_at,
            last_seen_at=last_seen_at,
        )
        db.add(incident)
        db.flush()
        self.link_incident_upload(db, incident=incident, upload=upload, relation_type="primary")
        return incident

    def link_incident_upload(
        self,
        db: Session,
        *,
        incident: Incident,
        upload: Upload,
        relation_type: str,
    ) -> IncidentUploadLink:
        existing = db.scalar(
            select(IncidentUploadLink).where(
                IncidentUploadLink.incident_id == incident.id,
                IncidentUploadLink.upload_id == upload.id,
            )
        )
        if existing is not None:
            return existing

        link = IncidentUploadLink(
            incident_id=incident.id,
            upload_id=upload.id,
            relation_type=relation_type,
        )
        db.add(link)
        upload.incident_count = 1
        db.flush()
        return link

    def link_incident_events(
        self,
        db: Session,
        *,
        incident: Incident,
        normalized_event_records: list[NormalizedEventRecord],
        detection_records: list[DetectionRecord],
        detection_candidates: list[DetectionCandidate],
    ) -> list[IncidentEventLink]:
        links: list[IncidentEventLink] = []
        for candidate, detection in zip(detection_candidates, detection_records, strict=True):
            normalized_event = normalized_event_records[candidate.normalized_event_index]
            link = IncidentEventLink(
                incident_id=incident.id,
                normalized_event_id=normalized_event.id,
                detection_id=detection.id,
                link_type="trigger",
            )
            db.add(link)
            links.append(link)
        db.flush()
        return links

    def add_score(
        self,
        db: Session,
        *,
        incident: Incident,
        score_view: IncidentScoreView,
    ) -> IncidentScore:
        for existing_score in incident.scores:
            existing_score.is_current = False

        score = IncidentScore(
            incident_id=incident.id,
            total_score=score_view.total_score,
            severity=score_view.severity,
            scoring_version=score_view.scoring_version,
            score_breakdown=score_view.model_dump(mode="json"),
        )
        db.add(score)
        db.flush()
        return score

    def update_incident_correlation(
        self,
        db: Session,
        *,
        incident: Incident,
        title: str,
        source_types: list[str],
        first_seen_at: datetime | None,
        last_seen_at: datetime | None,
        severity: str,
        risk_score: float,
        correlation_summary: str,
        correlation_context: dict[str, object],
    ) -> Incident:
        incident.title = title
        incident.source_types = source_types
        incident.first_seen_at = first_seen_at
        incident.last_seen_at = last_seen_at
        incident.severity = severity
        incident.risk_score = risk_score
        incident.correlation_summary = correlation_summary
        incident.correlation_context = correlation_context
        db.flush()
        return incident

    def add_llm_enrichment(
        self, db: Session, *, incident: Incident, analysis: LLMAnalysisOutput, provider: str = "ollama"
    ) -> IncidentEnrichment:
        return self.add_incident_enrichment(
            db,
            incident=incident,
            enrichment_type="llm_analysis",
            provider=provider,
            status="ready",
            summary=analysis.analysis_summary,
            payload=analysis.model_dump(mode="json"),
        )

    def add_incident_enrichment(
        self,
        db: Session,
        *,
        incident: Incident,
        enrichment_type: str,
        provider: str,
        status: str,
        summary: str | None,
        payload: dict[str, object],
    ) -> IncidentEnrichment:
        enrichment = IncidentEnrichment(
            incident_id=incident.id,
            enrichment_type=enrichment_type,
            provider=provider,
            status=status,
            summary=summary,
            payload=payload,
        )
        db.add(enrichment)
        db.flush()
        return enrichment

    def add_audit_log(
        self,
        db: Session,
        *,
        action: str,
        entity_type: str,
        entity_id: str,
        upload_id: int | None = None,
        incident_id: int | None = None,
        details: dict[str, object] | None = None,
        actor: str = "system",
    ) -> AuditLog:
        log = AuditLog(
            upload_id=upload_id,
            incident_id=incident_id,
            actor=actor,
            actor_type=AuditActorType.SYSTEM.value,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
        )
        db.add(log)
        db.flush()
        return log

    def get_ioc(
        self,
        db: Session,
        *,
        indicator: str,
        source: str,
        indicator_type: str = IndicatorType.IP.value,
    ) -> IOCache | None:
        stmt = select(IOCache).where(
            IOCache.indicator == indicator,
            IOCache.indicator_type == indicator_type,
            IOCache.source == source,
        )
        return db.scalar(stmt)

    def upsert_ioc(
        self,
        db: Session,
        *,
        indicator: str,
        is_malicious: bool,
        reputation_score: float,
        source: str = "local_detection_seed",
        indicator_type: str = IndicatorType.IP.value,
        attributes: dict[str, object] | None = None,
    ) -> IOCache:
        stmt = select(IOCache).where(
            IOCache.indicator == indicator,
            IOCache.indicator_type == indicator_type,
            IOCache.source == source,
        )
        existing = db.scalar(stmt)
        now = datetime.utcnow()
        if existing is not None:
            existing.is_malicious = existing.is_malicious or is_malicious
            existing.reputation_score = reputation_score
            existing.last_seen_at = now
            if attributes:
                merged_attributes = dict(existing.attributes or {})
                merged_attributes.update(attributes)
                existing.attributes = merged_attributes
            return existing

        cache_entry = IOCache(
            indicator=indicator,
            indicator_type=indicator_type,
            source=source,
            reputation_score=reputation_score,
            is_malicious=is_malicious,
            first_seen_at=now,
            last_seen_at=now,
            attributes=attributes or {"seeded_by": "phase1_detection_pipeline"},
        )
        db.add(cache_entry)
        db.flush()
        return cache_entry

    def get_incident_by_upload(self, db: Session, *, upload_id: int) -> Incident | None:
        stmt = (
            select(Incident)
            .join(IncidentUploadLink, IncidentUploadLink.incident_id == Incident.id)
            .where(IncidentUploadLink.upload_id == upload_id)
            .options(
                joinedload(Incident.upload),
                joinedload(Incident.upload_links).joinedload(IncidentUploadLink.upload),
                joinedload(Incident.enrichments),
                joinedload(Incident.scores),
                joinedload(Incident.analyst_reviews),
                joinedload(Incident.incident_events)
                .joinedload(IncidentEventLink.normalized_event),
                joinedload(Incident.incident_events).joinedload(IncidentEventLink.detection),
            )
        )
        return db.scalars(stmt).unique().one_or_none()

    def find_recent_correlatable_incidents(self, db: Session, *, earliest_seen: datetime | None) -> list[Incident]:
        stmt = (
            select(Incident)
            .options(
                joinedload(Incident.upload),
                joinedload(Incident.upload_links).joinedload(IncidentUploadLink.upload),
                joinedload(Incident.incident_events).joinedload(IncidentEventLink.normalized_event),
                joinedload(Incident.incident_events).joinedload(IncidentEventLink.detection),
            )
            .order_by(Incident.last_seen_at.desc(), Incident.created_at.desc())
        )
        if earliest_seen is not None:
            stmt = stmt.where((Incident.last_seen_at.is_not(None) & (Incident.last_seen_at >= earliest_seen)) | (Incident.created_at >= earliest_seen))
        return list(db.scalars(stmt).unique().all())
