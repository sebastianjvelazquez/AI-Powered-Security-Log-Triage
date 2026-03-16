import re

from app.models.schemas import NormalizedEvent
from app.parsers.base import BaseLogParser

AUTH_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<source_ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)


class AuthLogParser(BaseLogParser):
    source_type = "auth"

    def parse_line(self, line: str) -> NormalizedEvent | None:
        match = AUTH_PATTERN.search(line)
        if not match:
            return None

        status = "failure" if match.group("status") == "Failed" else "success"
        return NormalizedEvent(
            timestamp=match.group("timestamp"),
            hostname=match.group("hostname"),
            source_ip=match.group("source_ip"),
            destination_ip=None,
            user=match.group("user"),
            event_type="authentication",
            status=status,
            raw_message=line,
        )
