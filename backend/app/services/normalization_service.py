from app.models.schemas import NormalizedEvent
from app.parsers.factory import get_parser


def parse_and_normalize_logs(source_type: str, content: str) -> list[NormalizedEvent]:
    parser = get_parser(source_type)
    return parser.parse_content(content)
