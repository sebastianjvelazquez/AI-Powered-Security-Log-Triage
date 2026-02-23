MITRE_MAP: dict[str, list[str]] = {
    "multiple_failed_logins": ["T1110"],
    "suspicious_ip": ["T1078"],
    "privilege_escalation": ["T1068", "T1078.003"],
    "port_scanning_pattern": ["T1046"],
    "unusual_admin_access": ["T1078.004"],
}


def map_rules_to_mitre(rules: list[str]) -> list[str]:
    techniques: set[str] = set()
    for rule in rules:
        for technique in MITRE_MAP.get(rule, []):
            techniques.add(technique)
    return sorted(techniques)
