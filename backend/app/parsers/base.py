from abc import ABC, abstractmethod

from app.models.schemas import NormalizedEvent


class BaseLogParser(ABC):
    source_type: str

    @abstractmethod
    def parse_line(self, line: str) -> NormalizedEvent | None:
        """Parse a single log line into a normalized event."""

    def parse_content(self, content: str) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            parsed = self.parse_line(line)
            if parsed is not None:
                parsed.line_number = line_number
                events.append(parsed)
        return events
