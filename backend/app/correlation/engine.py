from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.core.config import get_settings
from app.models.db_models import Incident, NormalizedEventRecord
from app.models.schemas import SuspiciousEventOut

settings = get_settings()


@dataclass
class CorrelationDecision:
    incident: Incident | None
    relation_type: str
    title: str
    summary: str
    context: dict[str, object]


def _severity_rank(value: str) -> int:
    order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    return order.get(value, 0)


def _collect_incident_dimensions(incident: Incident) -> dict[str, set[str]]:
    source_ips: set[str] = set()
    users: set[str] = set()
    hostnames: set[str] = set()
    assets: set[str] = set()
    rule_names: set[str] = set()
    source_types: set[str] = set(incident.source_types)

    for link in incident.incident_events:
        event = link.normalized_event
        if event.source_ip:
            source_ips.add(event.source_ip)
        if event.user:
            users.add(event.user.lower())
        if event.hostname:
            hostnames.add(event.hostname.lower())
        if event.destination_ip:
            assets.add(event.destination_ip)
        if link.detection:
            rule_names.add(link.detection.rule_name)

    for upload_link in incident.upload_links:
        source_types.add(upload_link.upload.source_type)

    return {
        "source_ips": source_ips,
        "users": users,
        "hostnames": hostnames,
        "assets": assets,
        "rule_names": rule_names,
        "source_types": source_types,
    }


def _collect_current_dimensions(
    *,
    source_type: str,
    suspicious_events: list[SuspiciousEventOut],
    normalized_event_records: list[NormalizedEventRecord],
) -> dict[str, set[str]]:
    source_ips = {event.source_ip for event in suspicious_events if event.source_ip}
    users = {(event.user or "").lower() for event in suspicious_events if event.user}
    hostnames = {(event.hostname or "").lower() for event in suspicious_events if event.hostname}
    assets = {event.destination_ip for event in suspicious_events if event.destination_ip}
    if not hostnames:
        hostnames = {(record.hostname or "").lower() for record in normalized_event_records if record.hostname}
    if not assets:
        assets = {record.destination_ip for record in normalized_event_records if record.destination_ip}

    return {
        "source_ips": {value for value in source_ips if value},
        "users": {value for value in users if value},
        "hostnames": {value for value in hostnames if value},
        "assets": {value for value in assets if value},
        "rule_names": {event.rule_name for event in suspicious_events},
        "source_types": {source_type},
    }


def _build_chain_matches(existing_rules: set[str], current_rules: set[str], shared_source_ips: set[str], shared_users: set[str], combined_source_types: set[str], combined_assets: set[str]) -> list[str]:
    chains: list[str] = []
    combined_rules = existing_rules | current_rules

    if {"port_scanning_pattern", "multiple_failed_logins"}.issubset(combined_rules) and shared_source_ips:
        chains.append("port_scan_followed_by_auth_abuse")
    if {"multiple_failed_logins", "privilege_escalation"}.issubset(combined_rules) and shared_users:
        chains.append("failed_logins_followed_by_privilege_action")
    if "cloud" in combined_source_types and ("unusual_admin_access" in combined_rules or "suspicious_ip" in combined_rules):
        if shared_source_ips or shared_users:
            chains.append("cloud_access_with_related_identity_activity")
    if len(combined_assets) >= 2 and shared_source_ips:
        chains.append("repeated_activity_across_multiple_assets")

    return chains


def _summarize_correlation(chains: list[str], shared_source_ips: set[str], shared_users: set[str], shared_hostnames: set[str]) -> str:
    if chains:
        return f"Correlated by rule chain: {', '.join(chains)}"
    if shared_source_ips:
        return f"Correlated by recurring source IP activity: {', '.join(sorted(shared_source_ips))}"
    if shared_users:
        return f"Correlated by repeated account activity: {', '.join(sorted(shared_users))}"
    if shared_hostnames:
        return f"Correlated by repeated host targeting: {', '.join(sorted(shared_hostnames))}"
    return "No cross-source correlation match found."


def _pick_correlated_title(source_types: set[str], chains: list[str], severity: str, source_type: str, suspicious_events: list[SuspiciousEventOut]) -> str:
    if chains:
        label = chains[0].replace("_", " ")
        return f"{severity} correlated incident: {label}"
    if len(source_types) > 1:
        return f"{severity} multi-source incident across {', '.join(sorted(source_types))}"
    if suspicious_events:
        return f"{severity} {source_type.capitalize()} incident: {suspicious_events[0].rule_name.replace('_', ' ')}"
    return f"{source_type.capitalize()} upload review with no suspicious findings"


def correlate_incident(
    *,
    source_type: str,
    suspicious_events: list[SuspiciousEventOut],
    normalized_event_records: list[NormalizedEventRecord],
    existing_incidents: list[Incident],
    severity: str,
    risk_score: float,
) -> CorrelationDecision:
    current = _collect_current_dimensions(
        source_type=source_type,
        suspicious_events=suspicious_events,
        normalized_event_records=normalized_event_records,
    )
    if not suspicious_events:
        return CorrelationDecision(
            incident=None,
            relation_type="primary",
            title=f"{source_type.capitalize()} upload review with no suspicious findings",
            summary="No suspicious activity was available for correlation.",
            context={"matched": False, "reason": "no_suspicious_events"},
        )

    best_match: Incident | None = None
    best_score = 0
    best_context: dict[str, object] = {}
    best_summary = ""
    best_title = ""

    for incident in existing_incidents:
        existing = _collect_incident_dimensions(incident)
        shared_source_ips = existing["source_ips"] & current["source_ips"]
        shared_users = existing["users"] & current["users"]
        shared_hostnames = existing["hostnames"] & current["hostnames"]
        shared_assets = existing["assets"] & current["assets"]
        combined_source_types = existing["source_types"] | current["source_types"]
        combined_assets = existing["assets"] | current["assets"]
        chains = _build_chain_matches(
            existing_rules=existing["rule_names"],
            current_rules=current["rule_names"],
            shared_source_ips=shared_source_ips,
            shared_users=shared_users,
            combined_source_types=combined_source_types,
            combined_assets=combined_assets,
        )

        score = 0
        if shared_source_ips:
            score += 5
        if shared_users:
            score += 4
        if shared_hostnames or shared_assets:
            score += 3
        if len(combined_source_types) > 1:
            score += 3
        score += len(chains) * 4

        if score < 6:
            continue

        summary = _summarize_correlation(chains, shared_source_ips, shared_users, shared_hostnames)
        title = _pick_correlated_title(combined_source_types, chains, severity, source_type, suspicious_events)
        context = {
            "matched": True,
            "score": score,
            "shared_source_ips": sorted(shared_source_ips),
            "shared_users": sorted(shared_users),
            "shared_hostnames": sorted(shared_hostnames),
            "shared_assets": sorted(shared_assets),
            "chains": chains,
            "source_types": sorted(combined_source_types),
            "existing_incident_id": incident.id,
            "existing_severity": incident.severity,
            "incoming_severity": severity,
            "resolved_severity": severity if _severity_rank(severity) >= _severity_rank(incident.severity) else incident.severity,
            "resolved_risk_score": max(risk_score, incident.risk_score),
        }

        if score > best_score:
            best_match = incident
            best_score = score
            best_context = context
            best_summary = summary
            best_title = title

    if best_match is None:
        return CorrelationDecision(
            incident=None,
            relation_type="primary",
            title=_pick_correlated_title({source_type}, [], severity, source_type, suspicious_events),
            summary="No recent incident met deterministic correlation thresholds.",
            context={"matched": False, "source_types": [source_type]},
        )

    return CorrelationDecision(
        incident=best_match,
        relation_type="correlated",
        title=best_title,
        summary=best_summary,
        context=best_context,
    )


def correlation_lookback_start(*, last_seen_candidates: list[datetime | None]) -> datetime | None:
    timestamps = [value for value in last_seen_candidates if value is not None]
    if not timestamps:
        return datetime.utcnow() - timedelta(minutes=settings.correlation_window_minutes)
    return min(timestamps) - timedelta(minutes=settings.correlation_window_minutes)
