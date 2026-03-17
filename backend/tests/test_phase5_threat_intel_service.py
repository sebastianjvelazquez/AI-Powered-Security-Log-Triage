from app.enrichments.service import ThreatIntelEnrichmentService
from app.models.db_models import IOCache
from app.models.schemas import SuspiciousEventOut


def test_threat_intel_service_enriches_and_caches_indicators(db_session) -> None:
    service = ThreatIntelEnrichmentService()
    suspicious_events = [
        SuspiciousEventOut(
            timestamp="2026-03-01T10:00:00Z",
            source_ip="203.0.113.4",
            destination_ip="10.0.0.10",
            user="alice",
            event_type="authentication_failure",
            status="failed",
            rule_name="multiple_failed_logins",
            reason="Repeated failed login attempts from the same IP.",
            risk_weight=55,
            raw_message="failed login from 203.0.113.4",
        ),
        SuspiciousEventOut(
            timestamp="2026-03-01T10:20:00Z",
            source_ip="198.51.100.77",
            destination_ip="10.0.0.10",
            user="alice",
            event_type="authentication_failure",
            status="failed",
            rule_name="multiple_failed_logins",
            reason="Repeated failed login attempts from a second IP.",
            risk_weight=55,
            raw_message="failed login from 198.51.100.77",
        ),
    ]

    payload = service.enrich_suspicious_events(db_session, suspicious_events=suspicious_events)

    assert payload.provider == "local_mock_threat_intel"
    assert payload.summary.indicators_evaluated == 3
    assert payload.summary.malicious_indicator_count == 2
    assert "country_anomaly" in payload.summary.anomaly_flags
    assert "impossible_travel_suspected" in payload.summary.anomaly_flags

    cached_entries = db_session.query(IOCache).filter(IOCache.source == "local_mock_threat_intel").all()
    assert len(cached_entries) == 3

    payload_again = service.enrich_suspicious_events(db_session, suspicious_events=suspicious_events)
    cached_entries_again = db_session.query(IOCache).filter(IOCache.source == "local_mock_threat_intel").all()

    assert payload_again.summary.malicious_indicator_count == payload.summary.malicious_indicator_count
    assert len(cached_entries_again) == 3
