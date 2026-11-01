"""ARP and ping based host discovery."""
from __future__ import annotations

import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .netutils import target_hosts


def _enrich(ip: str, mac: str = "-", ttl: int | None = None,
            rtt: float | None = None) -> dict:
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        hostname = "-"
    return {"ip": ip, "mac": mac.upper(), "hostname": hostname,
            "ttl": ttl, "rtt_ms": rtt}


def arp_sweep(cidr: str, timeout: float = 2) -> list[dict]:
    """Discover hosts with Scapy ARP; raise on unavailable capture support."""
    from scapy.all import ARP, Ether, srp  # type: ignore
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                      timeout=timeout, verbose=False)
    return [_enrich(reply.psrc, reply.hwsrc) for _, reply in answered]


def _ping_one(ip: str) -> dict | None:
    system = __import__("platform").system()
    if system == "Windows":
        command = ["ping", "-n", "1", "-w", "500", ip]
    else:
        command = ["ping", "-c", "1", "-W", "1", ip]
    started = time.perf_counter()
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=2, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    output = result.stdout + result.stderr
    ttl_match = re.search(r"TTL[=|:](\d+)|ttl[=|:](\d+)", output)
    ttl = int(next(group for group in ttl_match.groups() if group)) if ttl_match else None
    return _enrich(ip, ttl=ttl, rtt=round((time.perf_counter() - started) * 1000, 2))


def ping_sweep(cidr: str) -> list[dict]:
    """Discover hosts using the operating system ping command."""
    with ThreadPoolExecutor(max_workers=64) as pool:
        results = [future.result() for future in
                   as_completed([pool.submit(_ping_one, ip) for ip in target_hosts(cidr)])]
    return [item for item in results if item]


def discover(cidr: str, method: str, local_ip: str) -> tuple[list[dict], str | None]:
    """Run requested discovery, falling back to ping when ARP is unavailable."""
    warning = None
    hosts: list[dict]
    if method == "arp":
        try:
            hosts = arp_sweep(cidr)
        except Exception as exc:  # network drivers and permissions vary by OS
            warning = f"ARP unavailable ({type(exc).__name__}); used ping sweep instead."
            hosts = ping_sweep(cidr)
    else:
        hosts = ping_sweep(cidr)
    if local_ip not in {host["ip"] for host in hosts}:
        hosts.append(_enrich(local_ip))
    return sorted(hosts, key=lambda item: tuple(int(part) for part in item["ip"].split("."))), warning
