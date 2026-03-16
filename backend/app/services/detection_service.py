from collections import defaultdict

from app.core.config import get_settings
from app.models.schemas import DetectionCandidate, NormalizedEvent
from app.utils.ip_utils import is_public_ip, is_suspicious_ip

settings = get_settings()


ADMIN_USERS = {"admin", "administrator", "root"}


def _extract_destination_port(event_type: str) -> str | None:
    if not event_type.startswith("network_"):
        return None
    parts = event_type.split("_")
    return parts[-1] if parts and parts[-1].isdigit() else None


def detect_suspicious_events(events: list[NormalizedEvent]) -> tuple[list[DetectionCandidate], dict[str, int]]:
    suspicious: list[DetectionCandidate] = []
    summary: dict[str, int] = defaultdict(int)

    failed_logins_by_source: dict[str, int] = defaultdict(int)
    blocked_ports_by_source: dict[str, set[str]] = defaultdict(set)

    for event in events:
        if event.status in {"failure", "failed"} and "auth" in event.event_type:
            key = event.source_ip or event.user or "unknown"
            failed_logins_by_source[key] += 1

        if event.status == "blocked" and event.source_ip:
            port = _extract_destination_port(event.event_type)
            if port:
                blocked_ports_by_source[event.source_ip].add(port)

    for normalized_event_index, event in enumerate(events):
        if event.status in {"failure", "failed"} and "auth" in event.event_type:
            key = event.source_ip or event.user or "unknown"
            if failed_logins_by_source[key] >= settings.failed_login_threshold:
                suspicious.append(
                    DetectionCandidate(
                        **event.model_dump(),
                        normalized_event_index=normalized_event_index,
                        rule_name="multiple_failed_logins",
                        reason=(
                            f"Detected {failed_logins_by_source[key]} failed login attempts for identity/source '{key}'"
                        ),
                        risk_weight=55,
                    )
                )
                summary["multiple_failed_logins"] += 1

        if event.event_type == "privilege_escalation" or "sudo" in event.raw_message.lower():
            suspicious.append(
                DetectionCandidate(
                    **event.model_dump(),
                    normalized_event_index=normalized_event_index,
                    rule_name="privilege_escalation",
                    reason="Possible privilege escalation behavior in log record",
                    risk_weight=70,
                )
            )
            summary["privilege_escalation"] += 1

        if is_suspicious_ip(event.source_ip):
            suspicious.append(
                DetectionCandidate(
                    **event.model_dump(),
                    normalized_event_index=normalized_event_index,
                    rule_name="suspicious_ip",
                    reason=f"Source IP {event.source_ip} matches suspicious network range",
                    risk_weight=45,
                )
            )
            summary["suspicious_ip"] += 1

        if event.status == "blocked" and event.source_ip:
            unique_ports = blocked_ports_by_source[event.source_ip]
            if len(unique_ports) >= settings.port_scan_threshold:
                suspicious.append(
                    DetectionCandidate(
                        **event.model_dump(),
                        normalized_event_index=normalized_event_index,
                        rule_name="port_scanning_pattern",
                        reason=(
                            f"Source {event.source_ip} probed {len(unique_ports)} unique blocked destination ports"
                        ),
                        risk_weight=60,
                    )
                )
                summary["port_scanning_pattern"] += 1

        if (event.user or "").lower() in ADMIN_USERS and event.status in {"success", "succeeded"}:
            if is_public_ip(event.source_ip):
                suspicious.append(
                    DetectionCandidate(
                        **event.model_dump(),
                        normalized_event_index=normalized_event_index,
                        rule_name="unusual_admin_access",
                        reason="Administrative account access from public source IP",
                        risk_weight=65,
                    )
                )
                summary["unusual_admin_access"] += 1

    return suspicious, dict(summary)
