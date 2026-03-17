from app.models.db_models import IncidentEnrichment
from app.models.schemas import LLMAnalysisOutput, LLMAnalysisResult, LLMExecutionTrace, LLMTaskTrace
from app.services.processing_pipeline_service import ProcessingPipelineService


class TraceStubAnalyzer:
    def analyze_with_fallback(self, bundle):  # noqa: ANN001
        analysis = LLMAnalysisOutput(
            severity="High",
            attack_type="Credential Access Attempt",
            mitre_techniques=["T1110"],
            confidence_score=78,
            analysis_summary="Validated structured detections indicate credential abuse activity with analyst relevance.",
            recommended_actions=["Block the source IP.", "Reset affected credentials."],
        )
        trace = LLMExecutionTrace(
            provider="ollama",
            model="llama3.1:8b",
            prompt_version="v2",
            used_fallback=True,
            fallback_reason="classification task failed validation",
            sanitized_bundle={
                "source_type": bundle.source_type,
                "detection_summary": bundle.detection_summary,
                "suspicious_events": [event.model_dump(mode="json") for event in bundle.suspicious_events],
            },
            tasks=[
                LLMTaskTrace(
                    task_name="attack_classification",
                    prompt_name="attack_classification.md",
                    raw_response=None,
                    used_fallback=True,
                    validation_error="classification task failed validation",
                )
            ],
        )
        return LLMAnalysisResult(analysis=analysis, trace=trace)


def test_pipeline_persists_llm_execution_trace(db_session) -> None:
    service = ProcessingPipelineService(llm_analyzer=TraceStubAnalyzer())
    content = "\n".join(
        [
            "2026-02-22T10:02:13Z host-a sshd[1245]: Failed password for invalid user admin from 203.0.113.4 port 50123 ssh2",
            "2026-02-22T10:02:14Z host-a sshd[1246]: Failed password for invalid user admin from 203.0.113.4 port 50124 ssh2",
            "2026-02-22T10:02:15Z host-a sshd[1247]: Failed password for invalid user admin from 203.0.113.4 port 50125 ssh2",
        ]
    )

    service.process_new_upload(
        db_session,
        filename="auth.log",
        source_type="auth",
        content=content,
    )

    trace_enrichment = (
        db_session.query(IncidentEnrichment).filter(IncidentEnrichment.enrichment_type == "llm_execution_trace").one()
    )

    assert trace_enrichment.provider == "ollama"
    assert trace_enrichment.payload["used_fallback"] is True
    assert trace_enrichment.payload["tasks"][0]["task_name"] == "attack_classification"
