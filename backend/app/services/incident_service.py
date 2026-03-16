from __future__ import annotations

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.llm.ollama_client import ResilientLLMAnalyzer
from app.models.db_models import Incident, Upload
from app.models.schemas import (
    AnalystReviewView,
    IncidentDetailResponse,
    IncidentEnrichmentView,
    IncidentHistoryItem,
    IncidentScoreBreakdown,
    IncidentScoreView,
    LLMAnalysisOutput,
    SuspiciousEventOut,
    UploadResponse,
)
from app.repositories.incident_repository import IncidentRepository
from app.services.processing_pipeline_service import ProcessingPipelineService


class IncidentService:
    def __init__(
        self,
        llm_analyzer: ResilientLLMAnalyzer | None = None,
        repository: IncidentRepository | None = None,
        pipeline_service: ProcessingPipelineService | None = None,
    ) -> None:
        self.repository = repository or IncidentRepository()
        self.pipeline_service = pipeline_service or ProcessingPipelineService(
            llm_analyzer=llm_analyzer,
            repository=self.repository,
        )

    def process_upload(self, db: Session, *, filename: str, source_type: str, content: str) -> UploadResponse:
        return self.pipeline_service.process_new_upload(
            db,
            filename=filename,
            source_type=source_type,
            content=content,
        )

    def get_history(self, db: Session) -> list[IncidentHistoryItem]:
        stmt = select(Incident, Upload).join(Upload, Incident.upload_id == Upload.id, isouter=True).order_by(desc(Incident.created_at))
        rows = db.execute(stmt).all()

        history: list[IncidentHistoryItem] = []
        for incident, upload in rows:
            history.append(
                IncidentHistoryItem(
                    incident_id=incident.id,
                    upload_id=upload.id if upload else None,
                    title=incident.title,
                    filename=upload.filename if upload else None,
                    source_type=upload.source_type if upload else (incident.source_types[0] if incident.source_types else "unknown"),
                    status=incident.status,
                    suspicious_count=upload.detection_count if upload else len(incident.incident_events),
                    severity=incident.severity,
                    risk_score=incident.risk_score,
                    uploaded_at=upload.uploaded_at if upload else incident.created_at,
                )
            )
        return history

    def get_incident_detail(self, db: Session, upload_id: int) -> IncidentDetailResponse | None:
        incident = self.repository.get_incident_by_upload(db, upload_id=upload_id)
        if incident is None:
            return None

        analysis = None
        enrichments: list[IncidentEnrichmentView] = []
        for enrichment in sorted(incident.enrichments, key=lambda item: item.created_at):
            enrichments.append(
                IncidentEnrichmentView(
                    enrichment_type=enrichment.enrichment_type,
                    provider=enrichment.provider,
                    status=enrichment.status,
                    summary=enrichment.summary,
                    payload=enrichment.payload,
                    created_at=enrichment.created_at,
                )
            )
            if enrichment.enrichment_type == "llm_analysis":
                analysis = LLMAnalysisOutput.model_validate(enrichment.payload)

        score = None
        current_score = next((item for item in sorted(incident.scores, key=lambda item: item.created_at, reverse=True) if item.is_current), None)
        if current_score is not None:
            score = IncidentScoreView(
                total_score=current_score.total_score,
                severity=current_score.severity,
                scoring_version=current_score.scoring_version,
                breakdown=IncidentScoreBreakdown.model_validate(current_score.score_breakdown),
            )

        suspicious_events = [
            SuspiciousEventOut(
                timestamp=link.normalized_event.timestamp_raw,
                source_ip=link.normalized_event.source_ip,
                destination_ip=link.normalized_event.destination_ip,
                user=link.normalized_event.user,
                event_type=link.normalized_event.event_type,
                status=link.normalized_event.status,
                rule_name=link.detection.rule_name if link.detection else "linked_event",
                reason=link.detection.reason if link.detection else "Associated incident evidence",
                risk_weight=link.detection.risk_weight if link.detection else 0,
                raw_message=link.normalized_event.raw_message,
            )
            for link in incident.incident_events
        ]
        analyst_reviews = [
            AnalystReviewView(
                reviewer=review.reviewer,
                disposition=review.disposition,
                notes=review.notes,
                override_severity=review.override_severity,
                override_mitre_techniques=review.override_mitre_techniques,
                override_recommended_actions=review.override_recommended_actions,
                created_at=review.created_at,
            )
            for review in incident.analyst_reviews
        ]

        return IncidentDetailResponse(
            incident_id=incident.id,
            upload_id=incident.upload.id if incident.upload else None,
            filename=incident.upload.filename if incident.upload else None,
            title=incident.title,
            status=incident.status,
            source_type=incident.upload.source_type if incident.upload else (incident.source_types[0] if incident.source_types else "unknown"),
            total_lines=incident.upload.total_lines if incident.upload else 0,
            suspicious_count=len(suspicious_events),
            uploaded_at=incident.upload.uploaded_at if incident.upload else incident.created_at,
            suspicious_events=suspicious_events,
            analysis=analysis,
            score=score,
            enrichments=enrichments,
            analyst_reviews=analyst_reviews,
        )
