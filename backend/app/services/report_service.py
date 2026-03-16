import json
from datetime import datetime

from app.models.schemas import IncidentDetailResponse


def build_report_json(detail: IncidentDetailResponse) -> dict:
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "incident": detail.model_dump(mode="json"),
    }


def build_report_markdown(detail: IncidentDetailResponse) -> str:
    analysis = detail.analysis
    score = detail.score
    lines = [
        "# Incident Report",
        "",
        f"- Incident ID: {detail.incident_id}",
        f"- Upload ID: {detail.upload_id if detail.upload_id is not None else 'N/A'}",
        f"- Title: {detail.title}",
        f"- Status: {detail.status}",
        f"- Filename: {detail.filename or 'N/A'}",
        f"- Source Type: {detail.source_type}",
        f"- Uploaded At: {detail.uploaded_at.isoformat()}Z",
        f"- Suspicious Events: {detail.suspicious_count}",
        "",
    ]

    if detail.correlation_summary:
        lines.extend(
            [
                "## Correlation Summary",
                "",
                detail.correlation_summary,
                "",
            ]
        )

    if analysis:
        lines.extend(
            [
                "## AI Triage Summary",
                "",
                f"- Severity: **{analysis.severity}**",
                f"- Attack Type: {analysis.attack_type}",
                f"- Confidence Score: {analysis.confidence_score}",
                f"- MITRE ATT&CK: {', '.join(analysis.mitre_techniques)}",
                "",
                "### Analyst Explanation",
                analysis.analysis_summary,
                "",
                "### Recommended Actions",
            ]
        )
        for action in analysis.recommended_actions:
            lines.append(f"- {action}")

    if score:
        lines.extend(
            [
                "",
                "## Score Breakdown",
                "",
                f"- Total Score: {score.total_score}",
                f"- Derived Severity: {score.severity}",
                f"- Scoring Version: {score.scoring_version}",
                f"- Rule Score: {score.breakdown.rule_score}",
                f"- LLM Confidence: {score.breakdown.llm_confidence}",
                f"- Asset Criticality: {score.breakdown.asset_criticality}",
            ]
        )

    lines.extend(["", "## Suspicious Events"])
    for idx, event in enumerate(detail.suspicious_events, start=1):
        lines.extend(
            [
                "",
                f"### Event {idx}",
                f"- Rule: {event.rule_name}",
                f"- Reason: {event.reason}",
                f"- Source IP: {event.source_ip or 'N/A'}",
                f"- Destination IP: {event.destination_ip or 'N/A'}",
                f"- User: {event.user or 'N/A'}",
                f"- Event Type: {event.event_type}",
                f"- Status: {event.status or 'N/A'}",
                f"- Risk Weight: {event.risk_weight}",
            ]
        )

    return "\n".join(lines)


def serialize_list(value: list[str]) -> str:
    return json.dumps(value)


def deserialize_list(value: str) -> list[str]:
    try:
        decoded = json.loads(value)
        return decoded if isinstance(decoded, list) else []
    except json.JSONDecodeError:
        return []
