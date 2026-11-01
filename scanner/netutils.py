"""Network discovery and target validation helpers."""
from __future__ import annotations

import ipaddress
import platform
import socket
from typing import Optional


def get_local_network() -> dict:
    """Return best-effort local interface, address, and RFC1918 subnet."""
    local_ip = "127.0.0.1"
    interface = "loopback"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
    except OSError:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            pass
    try:
        name = socket.if_nameindex()
        if name:
            interface = name[0][1]
    except (AttributeError, OSError):
        interface = "Wi-Fi" if platform.system() == "Windows" else "default"
    try:
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    except ValueError:
        network = ipaddress.ip_network("127.0.0.0/8")
    return {"local_ip": local_ip, "interface": interface,
            "subnet": str(network), "hostname": socket.gethostname()}


def validate_target(cidr: str) -> tuple[bool, Optional[str], str]:
    """Validate a target as an RFC1918 or loopback network no larger than /22."""
    try:
        network = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        return False, None, "Target must be a valid IPv4 CIDR network."
    if network.version != 4:
        return False, None, "Only IPv4 targets are supported."
    allowed = network.is_private or network.is_loopback
    if not allowed:
        return False, None, "Only private RFC1918 or loopback networks may be scanned."
    if network.prefixlen < 22:
        return False, None, "Target network must be /22 or smaller (at most 1024 addresses)."
    return True, str(network), ""


def target_hosts(cidr: str) -> list[str]:
    """Return usable addresses, excluding network and broadcast where applicable."""
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]
