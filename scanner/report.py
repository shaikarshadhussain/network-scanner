"""CSV and JSON report exporters."""
from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path(__file__).parent.parent / "reports"


def _paths() -> tuple[Path, Path]:
    REPORT_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    return REPORT_DIR / f"scan_{stamp}.csv", REPORT_DIR / f"scan_{stamp}.json"


def export_csv(result: dict) -> Path:
    """Write a flat CSV report and return its path."""
    csv_path, _ = _paths()
    with csv_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["ip", "mac", "vendor", "hostname", "os_guess", "ttl", "open_ports"])
        writer.writeheader()
        for host in result.get("hosts", []):
            writer.writerow({"ip": host["ip"], "mac": host.get("mac", "-"), "vendor": host.get("vendor", "Unknown"),
                             "hostname": host.get("hostname", "-"), "os_guess": host.get("os_guess", "Unknown"),
                             "ttl": host.get("ttl", "-"), "open_ports": ",".join(str(port["port"]) for port in host.get("ports", []))})
    return csv_path


def export_json(result: dict) -> Path:
    """Write a JSON report and return its path."""
    _, json_path = _paths()
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return json_path
