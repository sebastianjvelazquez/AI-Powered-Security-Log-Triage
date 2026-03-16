import re

from app.models.schemas import NormalizedEvent
from app.parsers.base import BaseLogParser

FIREWALL_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+FW\s+(?P<action>ALLOW|DROP)\s+SRC=(?P<src>[\d.]+)\s+DST=(?P<dst>[\d.]+)"
    r"\s+DPT=(?P<port>\d+)\s+PROTO=(?P<proto>\w+)"
)


class FirewallLogParser(BaseLogParser):
    source_type = "firewall"

    def parse_line(self, line: str) -> NormalizedEvent | None:
        match = FIREWALL_PATTERN.search(line)
        if not match:
            return None

        status = "blocked" if match.group("action") == "DROP" else "allowed"
        event_type = f"network_{match.group('proto').lower()}_{match.group('port')}"

        return NormalizedEvent(
            timestamp=match.group("timestamp"),
            hostname=None,
            source_ip=match.group("src"),
            destination_ip=match.group("dst"),
            user=None,
            event_type=event_type,
            status=status,
            raw_message=line,
        )
