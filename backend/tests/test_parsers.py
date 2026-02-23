from app.parsers.auth_parser import AuthLogParser
from app.parsers.cloud_parser import CloudLogParser
from app.parsers.firewall_parser import FirewallLogParser
from app.parsers.windows_parser import WindowsEventParser


def test_auth_parser_failed_login() -> None:
    parser = AuthLogParser()
    line = "2026-02-22T10:02:13Z host sshd[1245]: Failed password for invalid user admin from 203.0.113.4 port 50123 ssh2"

    event = parser.parse_line(line)

    assert event is not None
    assert event.user == "admin"
    assert event.source_ip == "203.0.113.4"
    assert event.status == "failure"


def test_firewall_parser_drop() -> None:
    parser = FirewallLogParser()
    line = "2026-02-22T10:10:00Z FW DROP SRC=198.51.100.77 DST=10.0.0.5 DPT=3389 PROTO=TCP"

    event = parser.parse_line(line)

    assert event is not None
    assert event.source_ip == "198.51.100.77"
    assert event.destination_ip == "10.0.0.5"
    assert event.status == "blocked"


def test_windows_parser_privilege_escalation() -> None:
    parser = WindowsEventParser()
    line = "2026-02-22T10:15:10Z EventID=4672 User=Administrator SrcIP=203.0.113.10 Status=SUCCESS Message=Special admin privileges assigned"

    event = parser.parse_line(line)

    assert event is not None
    assert event.event_type == "privilege_escalation"


def test_cloud_parser_console_login() -> None:
    parser = CloudLogParser()
    line = "2026-02-22T10:20:00Z provider=aws service=iam event=ConsoleLogin user=root sourceIp=198.51.100.200 status=Failed"

    event = parser.parse_line(line)

    assert event is not None
    assert event.user == "root"
    assert event.event_type == "cloud_iam_consolelogin"
