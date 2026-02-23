import re

from app.models.schemas import NormalizedEvent
from app.parsers.base import BaseLogParser

CLOUD_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+provider=(?P<provider>\w+)\s+service=(?P<service>\w+)\s+"
    r"event=(?P<event>\w+)\s+user=(?P<user>\S+)\s+sourceIp=(?P<source_ip>[\d.]+)\s+status=(?P<status>\w+)"
)


class CloudLogParser(BaseLogParser):
    source_type = "cloud"

    def parse_line(self, line: str) -> NormalizedEvent | None:
        match = CLOUD_PATTERN.search(line)
        if not match:
            return None

        event_type = f"cloud_{match.group('service').lower()}_{match.group('event').lower()}"

        return NormalizedEvent(
            timestamp=match.group("timestamp"),
            source_ip=match.group("source_ip"),
            destination_ip=None,
            user=match.group("user"),
            event_type=event_type,
            status=match.group("status").lower(),
            raw_message=line,
        )
