import ipaddress

SUSPICIOUS_NETWORKS = [
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
]


def is_suspicious_ip(ip: str | None) -> bool:
    if not ip:
        return False

    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return any(parsed in network for network in SUSPICIOUS_NETWORKS)


def is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False

    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return not (parsed.is_private or parsed.is_loopback or parsed.is_multicast)
