from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
import ipaddress
from typing import Protocol

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.schemas import SuspiciousEventOut, ThreatIntelEnrichmentPayload, ThreatIntelEnrichmentSummary, ThreatIntelIndicator
from app.repositories.incident_repository import IncidentRepository
from app.utils.time_utils import parse_event_timestamp

settings = get_settings()

LOCAL_IP_FIXTURES: dict[str, dict[str, object]] = {
    "203.0.113.4": {
        "country": "RU",
        "asn": "AS64550 Example Adversary Networks",
        "reputation_score": 94.0,
        "is_malicious": True,
        "tor_vpn": True,
        "known_indicator": True,
        "tags": ["credential_abuse", "scanner"],
    },
    "198.51.100.23": {
        "country": "DE",
        "asn": "AS64560 Example Hosting Transit",
        "reputation_score": 72.0,
        "is_malicious": True,
        "tor_vpn": False,
        "known_indicator": True,
        "tags": ["bruteforce"],
    },
    "198.51.100.77": {
        "country": "NL",
        "asn": "AS64561 Example VPN Edge",
        "reputation_score": 81.0,
        "is_malicious": True,
        "tor_vpn": True,
        "known_indicator": True,
        "tags": ["vpn", "suspicious_access"],
    },
    "192.0.2.200": {
        "country": "US",
        "asn": "AS64496 Example Cloud Services",
        "reputation_score": 18.0,
        "is_malicious": False,
        "tor_vpn": False,
        "known_indicator": False,
        "tags": ["cloud"],
    },
}


class ThreatIntelProvider(Protocol):
    name: str

    def lookup_ip(self, indicator: str) -> ThreatIntelIndicator:
        ...


class LocalThreatIntelProvider:
    name = "local_mock_threat_intel"

    def lookup_ip(self, indicator: str) -> ThreatIntelIndicator:
        fixture = LOCAL_IP_FIXTURES.get(indicator)
        if fixture is not None:
            return ThreatIntelIndicator(
                indicator=indicator,
                network_scope="public",
                is_private=False,
                country=str(fixture.get("country")) if fixture.get("country") else None,
                asn=str(fixture.get("asn")) if fixture.get("asn") else None,
                reputation_score=float(fixture.get("reputation_score", 0.0)),
                is_malicious=bool(fixture.get("is_malicious", False)),
                tor_vpn=bool(fixture.get("tor_vpn", False)),
                known_indicator=bool(fixture.get("known_indicator", False)),
                anomaly_flags=[],
                tags=[str(tag) for tag in fixture.get("tags", [])],
            )

        ip = ipaddress.ip_address(indicator)
        if ip.is_private:
            return ThreatIntelIndicator(
                indicator=indicator,
                network_scope="private",
                is_private=True,
                reputation_score=0.0,
                is_malicious=False,
                tor_vpn=False,
                known_indicator=False,
                anomaly_flags=[],
                tags=["internal"],
            )
        if ip.is_loopback:
            return ThreatIntelIndicator(
                indicator=indicator,
                network_scope="loopback",
                is_private=True,
                reputation_score=0.0,
                is_malicious=False,
                tor_vpn=False,
                known_indicator=False,
                anomaly_flags=[],
                tags=["loopback"],
            )

        return ThreatIntelIndicator(
            indicator=indicator,
            network_scope="public",
            is_private=False,
            country="Unknown",
            asn="AS0 Unattributed Public Network",
            reputation_score=12.0,
            is_malicious=False,
            tor_vpn=False,
            known_indicator=False,
            anomaly_flags=[],
            tags=["unattributed_public"],
        )


class ThreatIntelEnrichmentService:
    def __init__(
        self,
        repository: IncidentRepository | None = None,
        provider: ThreatIntelProvider | None = None,
    ) -> None:
        self.repository = repository or IncidentRepository()
        self.provider = provider or LocalThreatIntelProvider()

    def enrich_suspicious_events(
        self,
        db: Session,
        *,
        suspicious_events: list[SuspiciousEventOut],
    ) -> ThreatIntelEnrichmentPayload:
        indicators = self._collect_ip_indicators(suspicious_events)
        matches = [self._lookup_or_cache_indicator(db, indicator) for indicator in indicators]
        self._apply_user_country_anomalies(matches, suspicious_events)
        return ThreatIntelEnrichmentPayload(
            provider=self.provider.name,
            indicators=matches,
            summary=self._build_summary(matches),
        )

    def build_summary_text(self, payload: ThreatIntelEnrichmentPayload) -> str:
        summary = payload.summary
        if summary.indicators_evaluated == 0:
            return "No IP indicators were available for enrichment."

        parts = [
            f"Enriched {summary.indicators_evaluated} IP indicator(s)",
            f"{summary.malicious_indicator_count} flagged as known malicious",
            f"{summary.tor_vpn_count} identified as TOR/VPN-associated",
            f"highest reputation score {summary.highest_reputation_score}",
        ]
        if summary.anomaly_flags:
            parts.append(f"anomaly flags: {', '.join(summary.anomaly_flags)}")
        return "; ".join(parts) + "."

    def _collect_ip_indicators(self, suspicious_events: list[SuspiciousEventOut]) -> list[str]:
        indicators: list[str] = []
        seen: set[str] = set()
        for event in suspicious_events:
            for candidate in (event.source_ip, event.destination_ip):
                if candidate and candidate not in seen:
                    indicators.append(candidate)
                    seen.add(candidate)
        return indicators

    def _lookup_or_cache_indicator(self, db: Session, indicator: str) -> ThreatIntelIndicator:
        cached = self.repository.get_ioc(
            db,
            indicator=indicator,
            source=self.provider.name,
        )
        if cached is not None:
            return ThreatIntelIndicator(
                indicator=cached.indicator,
                network_scope=str((cached.attributes or {}).get("network_scope", "public")),
                is_private=bool((cached.attributes or {}).get("is_private", False)),
                country=(cached.attributes or {}).get("country"),
                asn=(cached.attributes or {}).get("asn"),
                reputation_score=float(cached.reputation_score or 0.0),
                is_malicious=cached.is_malicious,
                tor_vpn=bool((cached.attributes or {}).get("tor_vpn", False)),
                known_indicator=bool((cached.attributes or {}).get("known_indicator", cached.is_malicious)),
                anomaly_flags=[str(flag) for flag in (cached.attributes or {}).get("anomaly_flags", [])],
                tags=[str(tag) for tag in (cached.attributes or {}).get("tags", [])],
            )

        match = self.provider.lookup_ip(indicator)
        self.repository.upsert_ioc(
            db,
            indicator=match.indicator,
            source=self.provider.name,
            is_malicious=match.is_malicious,
            reputation_score=match.reputation_score,
            attributes={
                "network_scope": match.network_scope,
                "is_private": match.is_private,
                "country": match.country,
                "asn": match.asn,
                "tor_vpn": match.tor_vpn,
                "known_indicator": match.known_indicator,
                "anomaly_flags": match.anomaly_flags,
                "tags": match.tags,
                "cache_hours": settings.threat_intel_cache_hours,
            },
        )
        return match

    def _apply_user_country_anomalies(
        self,
        matches: list[ThreatIntelIndicator],
        suspicious_events: list[SuspiciousEventOut],
    ) -> None:
        indicator_map = {match.indicator: match for match in matches}
        countries_by_user: dict[str, set[str]] = defaultdict(set)
        timestamps_by_user: dict[str, list] = defaultdict(list)

        for event in suspicious_events:
            if not event.user or not event.source_ip:
                continue
            indicator = indicator_map.get(event.source_ip)
            if indicator is None or indicator.is_private or not indicator.country or indicator.country == "Unknown":
                continue
            countries_by_user[event.user].add(indicator.country)
            timestamp = parse_event_timestamp(event.timestamp)
            if timestamp is not None:
                timestamps_by_user[event.user].append(timestamp)

        for user, countries in countries_by_user.items():
            if len(countries) < 2:
                continue
            impossible_travel = False
            timestamps = timestamps_by_user.get(user, [])
            if len(timestamps) >= 2:
                impossible_travel = max(timestamps) - min(timestamps) <= timedelta(
                    minutes=settings.geo_velocity_window_minutes
                )

            for event in suspicious_events:
                if event.user != user or not event.source_ip:
                    continue
                indicator = indicator_map.get(event.source_ip)
                if indicator is None:
                    continue
                indicator.anomaly_flags.append("country_anomaly")
                if impossible_travel:
                    indicator.anomaly_flags.append("impossible_travel_suspected")

        for match in matches:
            if match.anomaly_flags:
                match.anomaly_flags = sorted(set(match.anomaly_flags))

    def _build_summary(self, matches: list[ThreatIntelIndicator]) -> ThreatIntelEnrichmentSummary:
        anomaly_flags = sorted({flag for match in matches for flag in match.anomaly_flags})
        return ThreatIntelEnrichmentSummary(
            indicators_evaluated=len(matches),
            public_ip_count=sum(1 for match in matches if not match.is_private),
            malicious_indicator_count=sum(1 for match in matches if match.is_malicious),
            tor_vpn_count=sum(1 for match in matches if match.tor_vpn),
            highest_reputation_score=max((match.reputation_score for match in matches), default=0.0),
            anomaly_flags=anomaly_flags,
        )
