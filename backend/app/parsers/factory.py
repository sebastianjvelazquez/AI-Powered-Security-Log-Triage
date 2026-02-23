from fastapi import HTTPException, status

from app.parsers.auth_parser import AuthLogParser
from app.parsers.base import BaseLogParser
from app.parsers.cloud_parser import CloudLogParser
from app.parsers.firewall_parser import FirewallLogParser
from app.parsers.windows_parser import WindowsEventParser

PARSER_REGISTRY: dict[str, type[BaseLogParser]] = {
    "auth": AuthLogParser,
    "firewall": FirewallLogParser,
    "windows": WindowsEventParser,
    "cloud": CloudLogParser,
}


def get_parser(source_type: str) -> BaseLogParser:
    parser_class = PARSER_REGISTRY.get(source_type.lower())
    if parser_class is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported source_type '{source_type}'. Expected one of: {sorted(PARSER_REGISTRY)}",
        )
    return parser_class()
