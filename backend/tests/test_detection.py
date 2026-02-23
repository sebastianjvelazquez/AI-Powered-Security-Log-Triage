from app.models.schemas import NormalizedEvent
from app.services.detection_service import detect_suspicious_events


def test_detection_multiple_failed_logins_and_suspicious_ip() -> None:
    events = [
        NormalizedEvent(
            timestamp="2026-02-22T10:00:00Z",
            source_ip="203.0.113.4",
            destination_ip=None,
            user="admin",
            event_type="authentication",
            status="failure",
            raw_message="failed login",
        ),
        NormalizedEvent(
            timestamp="2026-02-22T10:01:00Z",
            source_ip="203.0.113.4",
            destination_ip=None,
            user="admin",
            event_type="authentication",
            status="failure",
            raw_message="failed login",
        ),
        NormalizedEvent(
            timestamp="2026-02-22T10:02:00Z",
            source_ip="203.0.113.4",
            destination_ip=None,
            user="admin",
            event_type="authentication",
            status="failure",
            raw_message="failed login",
        ),
    ]

    suspicious, summary = detect_suspicious_events(events)

    assert len(suspicious) >= 3
    assert summary["multiple_failed_logins"] >= 1
    assert summary["suspicious_ip"] >= 1


def test_detection_port_scan_pattern() -> None:
    events = []
    for port in [22, 80, 443, 3389, 8080]:
        events.append(
            NormalizedEvent(
                timestamp="2026-02-22T11:00:00Z",
                source_ip="198.51.100.77",
                destination_ip="10.0.0.10",
                user=None,
                event_type=f"network_tcp_{port}",
                status="blocked",
                raw_message=f"blocked tcp {port}",
            )
        )

    suspicious, summary = detect_suspicious_events(events)

    assert summary["port_scanning_pattern"] >= 1
    assert any(event.rule_name == "port_scanning_pattern" for event in suspicious)
