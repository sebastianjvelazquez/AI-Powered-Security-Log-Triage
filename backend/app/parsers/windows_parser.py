import re

from app.models.schemas import NormalizedEvent
from app.parsers.base import BaseLogParser

WINDOWS_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+EventID=(?P<event_id>\d+)\s+User=(?P<user>\S+)\s+"
    r"SrcIP=(?P<source_ip>[\d.]+)\s+Status=(?P<status>\w+)\s+Message=(?P<message>.+)$"
)


class WindowsEventParser(BaseLogParser):
    source_type = "windows"

    def parse_line(self, line: str) -> NormalizedEvent | None:
        match = WINDOWS_PATTERN.search(line)
        if not match:
            return None

        event_id = match.group("event_id")
        message = match.group("message").lower()
        event_type = "windows_authentication"

        if event_id in {"4672", "4688"} and "admin" in message:
            event_type = "privilege_escalation"

        return NormalizedEvent(
            timestamp=match.group("timestamp"),
            hostname=None,
            source_ip=match.group("source_ip"),
            destination_ip=None,
            user=match.group("user"),
            event_type=event_type,
            status=match.group("status").lower(),
            raw_message=line,
        )
