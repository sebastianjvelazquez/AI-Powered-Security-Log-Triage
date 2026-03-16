from app.models.db_models import (
    AnalystReview,
    AuditLog,
    DetectionRecord,
    Incident,
    IncidentEnrichment,
    IncidentEventLink,
    IncidentScore,
    IOCache,
    NormalizedEventRecord,
    Upload,
)


def test_incident_centric_model_relationships(db_session) -> None:
    upload = Upload(
        filename="auth.log",
        source_type="auth",
        total_lines=4,
        normalized_event_count=3,
        detection_count=1,
        incident_count=1,
    )
    db_session.add(upload)
    db_session.flush()

    event = NormalizedEventRecord(
        upload_id=upload.id,
        event_index=0,
        line_number=1,
        timestamp_raw="2026-02-22T10:00:00Z",
        source_ip="203.0.113.10",
        destination_ip="10.0.0.15",
        user="admin",
        event_type="authentication",
        status="failure",
        raw_message="failed login",
    )
    db_session.add(event)
    db_session.flush()

    detection = DetectionRecord(
        upload_id=upload.id,
        normalized_event_id=event.id,
        rule_name="multiple_failed_logins",
        reason="threshold met",
        risk_weight=55,
        detection_context={"attempts": 3},
    )
    db_session.add(detection)
    db_session.flush()

    incident = Incident(
        upload_id=upload.id,
        title="High auth incident: multiple failed logins",
        status="new",
        source_types=["auth"],
        severity="High",
        risk_score=72.5,
        summary="Correlated auth abuse pattern",
    )
    db_session.add(incident)
    db_session.flush()

    db_session.add(
        IncidentEventLink(
            incident_id=incident.id,
            normalized_event_id=event.id,
            detection_id=detection.id,
            link_type="trigger",
        )
    )
    db_session.add(
        IncidentEnrichment(
            incident_id=incident.id,
            enrichment_type="llm_analysis",
            provider="ollama",
            status="ready",
            summary="Structured summary",
            payload={"severity": "High"},
        )
    )
    db_session.add(
        IncidentScore(
            incident_id=incident.id,
            total_score=72.5,
            severity="High",
            score_breakdown={"rule_score": 55},
            scoring_version="v1",
        )
    )
    db_session.add(
        AnalystReview(
            incident_id=incident.id,
            reviewer="analyst@example.com",
            disposition="needs_review",
            notes="Initial look",
        )
    )
    db_session.add(
        AuditLog(
            incident_id=incident.id,
            upload_id=upload.id,
            actor="system",
            actor_type="system",
            action="incident.created",
            entity_type="incident",
            entity_id=str(incident.id),
            details={"title": incident.title},
        )
    )
    db_session.add(
        IOCache(
            indicator="203.0.113.10",
            indicator_type="ip",
            source="local_detection_seed",
            reputation_score=55.0,
            is_malicious=True,
        )
    )
    db_session.commit()

    persisted_upload = db_session.get(Upload, upload.id)
    assert persisted_upload is not None
    assert len(persisted_upload.normalized_events) == 1
    assert len(persisted_upload.detections) == 1
    assert len(persisted_upload.incidents) == 1

    persisted_incident = db_session.get(Incident, incident.id)
    assert persisted_incident is not None
    assert len(persisted_incident.incident_events) == 1
    assert len(persisted_incident.enrichments) == 1
    assert len(persisted_incident.scores) == 1
    assert len(persisted_incident.analyst_reviews) == 1
    assert len(persisted_incident.audit_logs) == 1
