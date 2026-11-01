"""Vendor and lightweight heuristic device fingerprinting."""
from __future__ import annotations

import csv
from pathlib import Path


def vendor_lookup(mac: str) -> str:
    """Look up the first three MAC octets in the bundled OUI table."""
    prefix = mac.upper().replace(":", "-")[:8]
    try:
        with (Path(__file__).parent.parent / "data" / "oui.csv").open(newline="") as file:
            for row in csv.DictReader(file):
                if row["prefix"].upper() == prefix:
                    return row["vendor"]
    except (OSError, KeyError):
        pass
    return "Unknown"


def guess_os(ttl: int | None, ports: list[dict]) -> str:
    """Guess an OS from TTL and characteristic TCP services."""
    numbers = {item["port"] for item in ports}
    if numbers & {3389, 445, 135}:
        return "Windows (TTL 128)"
    if 22 in numbers:
        return "Linux / Android / iOS / Embedded (TTL 64)"
    if numbers & {9100, 631}:
        return "Printer"
    if 554 in numbers:
        return "Camera / embedded"
    if ttl is not None and ttl <= 64:
        return "Linux / Android / iOS / Embedded (TTL 64)"
    if ttl is not None and ttl <= 128:
        return "Windows (TTL 128)"
    return "Network device (TTL 255)" if ttl else "Unknown"


def classify_device(host: dict) -> str:
    """Classify a host using service and vendor signals."""
    ports = {item["port"] for item in host.get("ports", [])}
    vendor = host.get("vendor", "").lower()
    if ports & {9100, 631}:
        return "Printer"
    if 554 in ports:
        return "Camera"
    if ports & {53, 67, 80, 443} and not ports & {22, 135, 445, 3389}:
        return "Router"
    if any(word in vendor for word in ("apple", "samsung", "xiaomi", "realme", "huawei")):
        return "Phone / IoT"
    return "PC" if ports & {22, 135, 445, 3389} else "IoT"
