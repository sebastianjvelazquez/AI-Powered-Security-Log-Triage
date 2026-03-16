from __future__ import annotations

from collections.abc import Callable, Iterable

from sqlalchemy.orm import Session

from app.correlation.engine import correlate_incident, correlation_lookback_start
from app.core.config import get_settings
from app.llm.ollama_client import ResilientLLMAnalyzer
from app.models.db_models import Upload
from app.models.schemas import (
    DetectionCandidate,
    IncidentBundle,
    LLMAnalysisOutput,
    SuspiciousEventOut,
    UploadResponse,
)
from app.repositories.incident_repository import IncidentRepository
from app.services.detection_service import detect_suspicious_events
from app.services.normalization_service import parse_and_normalize_logs
from app.services.risk_scoring import build_incident_score
from app.utils.time_utils import parse_event_timestamp

settings = get_settings()

StageCallback = Callable[[str], None]


def _candidate_to_api_event(candidate: DetectionCandidate) -> SuspiciousEventOut:
    return SuspiciousEventOut(**candidate.model_dump(exclude={"normalized_event_index"}))


def _pick_incident_title(source_type: str, suspicious_events: list[SuspiciousEventOut], severity: str) -> str:
    if not suspicious_events:
        return f"{source_type.capitalize()} upload review with no suspicious findings"

    primary_rule = suspicious_events[0].rule_name.replace("_", " ")
    return f"{severity} {source_type.capitalize()} incident: {primary_rule}"


def _pick_time_bounds(values: Iterable) -> tuple[object | None, object | None]:
    filtered = [value for value in values if value is not None]
    if not filtered:
        return None, None
    return min(filtered), max(filtered)


def _non_null_values(*values: object | None) -> list[object]:
    filtered = [value for value in values if value is not None]
    return filtered


class ProcessingPipelineService:
    def __init__(
        self,
        llm_analyzer: ResilientLLMAnalyzer | None = None,
        repository: IncidentRepository | None = None,
    ) -> None:
        self.llm_analyzer = llm_analyzer or ResilientLLMAnalyzer()
        self.repository = repository or IncidentRepository()

    def process_new_upload(
        self,
        db: Session,
        *,
        filename: str,
        source_type: str,
        content: str,
        storage_path: str | None = None,
        on_stage_change: StageCallback | None = None,
    ) -> UploadResponse:
        upload = self.repository.create_upload(
            db,
            filename=filename,
            source_type=source_type,
            total_lines=len(content.splitlines()),
            normalized_event_count=0,
            storage_path=storage_path,
            processing_status="uploaded",
        )
        self.repository.add_audit_log(
            db,
            action="upload.created",
            entity_type="upload",
            entity_id=str(upload.id),
            upload_id=upload.id,
            details={"filename": filename, "source_type": source_type},
        )
        return self.process_existing_upload(
            db,
            upload=upload,
            source_type=source_type,
            content=content,
            on_stage_change=on_stage_change,
        )

    def process_existing_upload(
        self,
        db: Session,
        *,
        upload: Upload,
        source_type: str,
        content: str,
        on_stage_change: StageCallback | None = None,
    ) -> UploadResponse:
        def notify(stage: str) -> None:
            upload.processing_status = stage
            if on_stage_change is not None:
                on_stage_change(stage)

        notify("parsing")
        normalized_events = parse_and_normalize_logs(source_type=source_type, content=content)
        upload.total_lines = len(content.splitlines())
        upload.normalized_event_count = len(normalized_events)
        normalized_event_records = self.repository.create_normalized_events(
            db,
            upload=upload,
            normalized_events=normalized_events,
        )

        notify("detecting")
        detection_candidates, detection_summary = detect_suspicious_events(normalized_events)
        suspicious_events = [_candidate_to_api_event(candidate) for candidate in detection_candidates]
        detection_records = self.repository.create_detections(
            db,
            upload=upload,
            normalized_event_records=normalized_event_records,
            detection_candidates=detection_candidates,
        )

        notify("correlating")
        first_seen_at, last_seen_at = _pick_time_bounds(
            parse_event_timestamp(event.timestamp_raw) for event in normalized_event_records
        )

        notify("enriching")
        if suspicious_events:
            bundle = IncidentBundle(
                source_type=source_type,
                suspicious_events=suspicious_events,
                detection_summary=detection_summary,
            )
            llm_output = self.llm_analyzer.analyze_with_fallback(bundle)
            initial_score = build_incident_score(
                rule_weights=[event.risk_weight for event in suspicious_events],
                llm_analysis=llm_output,
                asset_criticality=settings.asset_criticality,
                suspicious_event_count=len(suspicious_events),
                detection_summary=detection_summary,
                threat_intel_hits=0,
                correlation_strength=0,
            )
            risk_score = initial_score.total_score
            final_severity = initial_score.severity
            llm_analysis_for_response = llm_output.model_copy(update={"severity": final_severity})
        else:
            risk_score = 0.0
            final_severity = "Low"
            llm_analysis_for_response = LLMAnalysisOutput(
                severity=final_severity,
                attack_type="No actionable suspicious activity detected",
                mitre_techniques=["T1595"],
                confidence_score=100,
                analysis_summary="No suspicious patterns were identified by deterministic detection rules.",
                recommended_actions=["Archive this log review and continue standard monitoring."],
            )

        earliest_seen = correlation_lookback_start(
            last_seen_candidates=[first_seen_at, last_seen_at],
        )
        correlation_candidates = self.repository.find_recent_correlatable_incidents(
            db,
            earliest_seen=earliest_seen,
        )
        correlation_decision = correlate_incident(
            source_type=source_type,
            suspicious_events=suspicious_events,
            normalized_event_records=normalized_event_records,
            existing_incidents=[candidate for candidate in correlation_candidates if candidate.upload_id != upload.id],
            severity=final_severity,
            risk_score=risk_score,
        )

        incident = correlation_decision.incident
        if incident is None:
            incident = self.repository.create_incident(
                db,
                upload=upload,
                asset=next((record.asset for record in normalized_event_records if record.asset is not None), None),
                title=correlation_decision.title,
                severity=final_severity,
                risk_score=risk_score,
                summary=llm_analysis_for_response.analysis_summary,
                source_types=[source_type],
                first_seen_at=first_seen_at,
                last_seen_at=last_seen_at,
                correlation_summary=correlation_decision.summary,
                correlation_context=correlation_decision.context,
            )
        else:
            self.repository.link_incident_upload(
                db,
                incident=incident,
                upload=upload,
                relation_type=correlation_decision.relation_type,
            )
            merged_source_types = sorted(set(incident.source_types) | {source_type})
            merged_first_seen_values = _non_null_values(incident.first_seen_at, first_seen_at)
            merged_last_seen_values = _non_null_values(incident.last_seen_at, last_seen_at)
            merged_first_seen = min(merged_first_seen_values) if merged_first_seen_values else None
            merged_last_seen = max(merged_last_seen_values) if merged_last_seen_values else None
            resolved_severity = final_severity if risk_score >= incident.risk_score else incident.severity
            resolved_score = max(risk_score, incident.risk_score)
            self.repository.update_incident_correlation(
                db,
                incident=incident,
                title=correlation_decision.title,
                source_types=merged_source_types,
                first_seen_at=merged_first_seen,
                last_seen_at=merged_last_seen,
                severity=resolved_severity,
                risk_score=resolved_score,
                correlation_summary=correlation_decision.summary,
                correlation_context=correlation_decision.context,
            )

        self.repository.link_incident_events(
            db,
            incident=incident,
            normalized_event_records=normalized_event_records,
            detection_records=detection_records,
            detection_candidates=detection_candidates,
        )
        self.repository.add_llm_enrichment(db, incident=incident, analysis=llm_analysis_for_response)

        notify("scoring")
        correlation_strength = int(correlation_decision.context.get("score", 0)) if correlation_decision.context else 0
        score_view = build_incident_score(
            rule_weights=[event.risk_weight for event in suspicious_events],
            llm_analysis=llm_analysis_for_response,
            asset_criticality=settings.asset_criticality,
            suspicious_event_count=len(suspicious_events),
            detection_summary=detection_summary,
            threat_intel_hits=0,
            correlation_strength=correlation_strength,
        )
        incident.severity = score_view.severity
        incident.risk_score = score_view.total_score
        self.repository.add_score(
            db,
            incident=incident,
            score_view=score_view,
        )
        self.repository.add_audit_log(
            db,
            action="incident.correlated" if correlation_decision.incident is not None else "incident.created",
            entity_type="incident",
            entity_id=str(incident.id),
            upload_id=upload.id,
            incident_id=incident.id,
            details={
                "severity": incident.severity,
                "title": incident.title,
                "correlation_summary": correlation_decision.summary,
                "relation_type": correlation_decision.relation_type,
            },
        )

        seen_iocs: set[str] = set()
        for suspicious_event in suspicious_events:
            if suspicious_event.source_ip and suspicious_event.source_ip not in seen_iocs:
                seen_iocs.add(suspicious_event.source_ip)
                self.repository.upsert_ioc(
                    db,
                    indicator=suspicious_event.source_ip,
                    is_malicious=True,
                    reputation_score=float(suspicious_event.risk_weight),
                )

        notify("report_generation")
        self.repository.add_audit_log(
            db,
            action="report.ready",
            entity_type="incident",
            entity_id=str(incident.id),
            upload_id=upload.id,
            incident_id=incident.id,
            details={"report_formats": ["json", "markdown"]},
        )

        notify("completed")
        db.commit()
        return UploadResponse(
            upload_id=upload.id,
            incident_id=incident.id,
            filename=upload.filename,
            source_type=upload.source_type,
            title=incident.title,
            status=incident.status,
            total_lines=upload.total_lines,
            suspicious_count=len(suspicious_events),
            suspicious_events=suspicious_events,
            severity=incident.severity,
            risk_score=incident.risk_score,
            analysis=llm_analysis_for_response,
        )
