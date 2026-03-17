MITRE_MAP: dict[str, list[str]] = {
    "multiple_failed_logins": ["T1110"],
    "suspicious_ip": ["T1078"],
    "privilege_escalation": ["T1068", "T1078.003"],
    "port_scanning_pattern": ["T1046"],
    "unusual_admin_access": ["T1078.004"],
}


ALLOWED_MITRE_IDS = frozenset(
    technique
    for mapped_techniques in MITRE_MAP.values()
    for technique in mapped_techniques
)


def map_rules_to_mitre(rules: list[str]) -> list[str]:
    techniques: set[str] = set()
    for rule in rules:
        for technique in MITRE_MAP.get(rule, []):
            techniques.add(technique)
    return sorted(techniques)


def allowed_mitre_ids() -> set[str]:
    return set(ALLOWED_MITRE_IDS)


def is_allowed_mitre_id(technique: str) -> bool:
    return technique in ALLOWED_MITRE_IDS


def filter_allowed_mitre_ids(techniques: list[str]) -> list[str]:
    return sorted({technique for technique in techniques if is_allowed_mitre_id(technique)})
