"""Threaded TCP connect scanner and simple banner collection."""
from __future__ import annotations

import json
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SERVICES = json.loads((Path(__file__).parent.parent / "data" / "services.json").read_text())


def parse_ports(preset: str, custom: str = "") -> list[int]:
    """Parse a named preset or comma-separated ports/ranges."""
    if preset == "top100":
        # The bundled service map names the common ports; these final RPC ports
        # complete the practical 100-port preset without duplicating entries.
        ports = sorted(int(port) for port in SERVICES)
        return sorted(set(ports + [49156, 49157, 49158, 49159]))
    if preset == "1-1024":
        return list(range(1, 1025))
    values: set[int] = set()
    for part in custom.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = (int(value) for value in part.split("-", 1))
            values.update(range(start, end + 1))
        else:
            values.add(int(part))
    if not values or any(port < 1 or port > 65535 for port in values):
        raise ValueError("Custom ports must be between 1 and 65535.")
    return sorted(values)


def _banner(sock: socket.socket, ip: str, port: int) -> str:
    try:
        if port in (80, 8080, 5000):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        if port == 443:
            context = ssl._create_unverified_context()
            with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
                return f"TLS {tls_sock.version() or ''}".strip()
        sock.settimeout(0.5)
        data = sock.recv(128)
        text = data.decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ").strip()
        if port in (80, 8080, 5000):
            for line in text.split("  "):
                if line.lower().startswith("server:"):
                    return line.strip()
        return text[:128]
    except (OSError, ssl.SSLError):
        return "TLS" if port == 443 else "-"


def scan_port(ip: str, port: int, timeout: float = 0.5, banner: bool = True) -> dict | None:
    """Check one TCP port and return an open-port record."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    try:
        response = _banner(sock, ip, port) if banner else "-"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return {"port": port, "state": "open", "service": SERVICES.get(str(port), "unknown"),
            "banner": response}


def scan_host(ip: str, ports: list[int], threads: int = 100, timeout: float = 0.5,
              banner: bool = True, cancel_event=None) -> list[dict]:
    """Scan a host concurrently, stopping submission when cancellation is requested."""
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(int(threads), 200))) as pool:
        futures = [pool.submit(scan_port, ip, port, timeout, banner) for port in ports]
        for future in as_completed(futures):
            if cancel_event is not None and cancel_event.is_set():
                break
            result = future.result()
            if result:
                results.append(result)
    return sorted(results, key=lambda item: item["port"])
