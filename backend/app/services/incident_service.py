from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.llm.ollama_client import ResilientLLMAnalyzer
from app.models.db_models import AIAnalysis, LogUpload, SuspiciousEvent
from app.models.schemas import (
    IncidentBundle,
    IncidentDetailResponse,
    IncidentHistoryItem,
    LLMAnalysisOutput,
    SuspiciousEventOut,
    UploadResponse,
)
from app.services.detection_service import detect_suspicious_events
from app.services.normalization_service import parse_and_normalize_logs
from app.services.report_service import deserialize_list, serialize_list
from app.services.risk_scoring import compute_risk_score, severity_from_score

settings = get_settings()


class IncidentService:
    def __init__(self) -> None:
        self.llm_analyzer = ResilientLLMAnalyzer()

    def process_upload(self, db: Session, *, filename: str, source_type: str, content: str) -> UploadResponse:
        normalized_events = parse_and_normalize_logs(source_type=source_type, content=content)
        suspicious_events, detection_summary = detect_suspicious_events(normalized_events)

        upload = LogUpload(
            filename=filename,
            source_type=source_type,
            total_lines=len(content.splitlines()),
            suspicious_count=len(suspicious_events),
        )
        db.add(upload)
        db.flush()

        for event in suspicious_events:
            db.add(
                SuspiciousEvent(
                    upload_id=upload.id,
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    user=event.user,
                    event_type=event.event_type,
                    status=event.status,
                    rule_name=event.rule_name,
                    reason=event.reason,
                    risk_weight=event.risk_weight,
                    raw_message=event.raw_message,
                )
            )

        if suspicious_events:
            bundle = IncidentBundle(
                source_type=source_type,
                suspicious_events=suspicious_events,
                detection_summary=detection_summary,
            )
            llm_output = self.llm_analyzer.analyze_with_fallback(bundle)
            risk_score = compute_risk_score(
                rule_weights=[event.risk_weight for event in suspicious_events],
                llm_analysis=llm_output,
                asset_criticality=settings.asset_criticality,
            )
            final_severity = severity_from_score(risk_score)

            analysis = AIAnalysis(
                upload_id=upload.id,
                severity=final_severity,
                attack_type=llm_output.attack_type,
                mitre_techniques=serialize_list(llm_output.mitre_techniques),
                confidence_score=llm_output.confidence_score,
                analysis_summary=llm_output.analysis_summary,
                recommended_actions=serialize_list(llm_output.recommended_actions),
                risk_score=risk_score,
            )
            db.add(analysis)

            llm_analysis_for_response = LLMAnalysisOutput(
                severity=final_severity,
                attack_type=llm_output.attack_type,
                mitre_techniques=llm_output.mitre_techniques,
                confidence_score=llm_output.confidence_score,
                analysis_summary=llm_output.analysis_summary,
                recommended_actions=llm_output.recommended_actions,
            )
        else:
            risk_score = 0.0
            llm_analysis_for_response = LLMAnalysisOutput(
                severity="Low",
                attack_type="No actionable suspicious activity detected",
                mitre_techniques=["T1595"],
                confidence_score=100,
                analysis_summary="No suspicious patterns were identified by deterministic detection rules.",
                recommended_actions=[
                    "Archive this log review and continue standard monitoring.",
                ],
            )
            analysis = AIAnalysis(
                upload_id=upload.id,
                severity="Low",
                attack_type=llm_analysis_for_response.attack_type,
                mitre_techniques=serialize_list(llm_analysis_for_response.mitre_techniques),
                confidence_score=llm_analysis_for_response.confidence_score,
                analysis_summary=llm_analysis_for_response.analysis_summary,
                recommended_actions=serialize_list(llm_analysis_for_response.recommended_actions),
                risk_score=risk_score,
            )
            db.add(analysis)

        db.commit()

        return UploadResponse(
            upload_id=upload.id,
            filename=upload.filename,
            source_type=upload.source_type,
            total_lines=upload.total_lines,
            suspicious_count=upload.suspicious_count,
            suspicious_events=suspicious_events,
            severity=llm_analysis_for_response.severity,
            risk_score=risk_score,
            analysis=llm_analysis_for_response,
        )

    def get_history(self, db: Session) -> list[IncidentHistoryItem]:
        stmt = (
            select(LogUpload, AIAnalysis)
            .join(AIAnalysis, LogUpload.id == AIAnalysis.upload_id, isouter=True)
            .order_by(desc(LogUpload.uploaded_at))
        )
        rows = db.execute(stmt).all()

        history: list[IncidentHistoryItem] = []
        for upload, analysis in rows:
            history.append(
                IncidentHistoryItem(
                    upload_id=upload.id,
                    filename=upload.filename,
                    source_type=upload.source_type,
                    suspicious_count=upload.suspicious_count,
                    severity=analysis.severity if analysis else None,
                    risk_score=analysis.risk_score if analysis else None,
                    uploaded_at=upload.uploaded_at,
                )
            )
        return history

    def get_incident_detail(self, db: Session, upload_id: int) -> IncidentDetailResponse | None:
        upload = db.get(LogUpload, upload_id)
        if upload is None:
            return None

        events = db.scalars(select(SuspiciousEvent).where(SuspiciousEvent.upload_id == upload_id)).all()
        analysis = db.scalar(select(AIAnalysis).where(AIAnalysis.upload_id == upload_id))

        analysis_output = None
        risk_score = None
        if analysis:
            risk_score = analysis.risk_score
            analysis_output = LLMAnalysisOutput(
                severity=analysis.severity,
                attack_type=analysis.attack_type,
                mitre_techniques=deserialize_list(analysis.mitre_techniques),
                confidence_score=analysis.confidence_score,
                analysis_summary=analysis.analysis_summary,
                recommended_actions=deserialize_list(analysis.recommended_actions),
            )

        suspicious_events = [
            SuspiciousEventOut(
                timestamp=item.timestamp,
                source_ip=item.source_ip,
                destination_ip=item.destination_ip,
                user=item.user,
                event_type=item.event_type,
                status=item.status,
                rule_name=item.rule_name,
                reason=item.reason,
                risk_weight=item.risk_weight,
                raw_message=item.raw_message,
            )
            for item in events
        ]

        return IncidentDetailResponse(
            upload_id=upload.id,
            filename=upload.filename,
            source_type=upload.source_type,
            total_lines=upload.total_lines,
            suspicious_count=upload.suspicious_count,
            uploaded_at=upload.uploaded_at,
            suspicious_events=suspicious_events,
            analysis=analysis_output,
            risk_score=risk_score,
        )
