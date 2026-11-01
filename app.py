"""Flask dashboard and background job manager for Advanced Network Scanner."""
from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

from scanner.discovery import discover
from scanner.fingerprint import classify_device, guess_os, vendor_lookup
from scanner.netutils import get_local_network, validate_target
from scanner.portscan import parse_ports, scan_host
from scanner.report import export_csv, export_json

app = Flask(__name__)
Path("reports").mkdir(exist_ok=True)
NETWORK = get_local_network()
JOBS: dict[str, dict] = {}
HISTORY: list[dict] = []


def log(message: str) -> None:
    print(message, flush=True)


def run_scan(job_id: str, options: dict) -> None:
    job = JOBS[job_id]
    started = time.perf_counter()
    try:
        target = options["target"]
        log(f"[SCAN] Phase 1 - Host discovery ({options['method'].upper()} sweep)")
        job.update(phase="Host discovery", progress=5)
        hosts, warning = discover(target, options["method"], NETWORK["local_ip"])
        job.update(hosts_found=len(hosts), warning=warning, progress=25)
        ports = parse_ports(options["ports"], options.get("custom_ports", ""))
        log("[SCAN] Phase 2 - Port scan + banner grabbing (TCP connect)")
        all_hosts = []
        for index, host in enumerate(hosts):
            if job["cancel"].is_set():
                job.update(state="cancelled", phase="Cancelled")
                return
            host["vendor"] = vendor_lookup(host.get("mac", "-"))
            host["ports"] = scan_host(host["ip"], ports, options["threads"], options["timeout"], options["banner"], job["cancel"])
            host["open_ports"] = len(host["ports"])
            host["os_guess"] = guess_os(host.get("ttl"), host["ports"]) if options["os_guess"] else "Disabled"
            host["device_type"] = classify_device(host)
            all_hosts.append(host)
            job["ports_found"] = sum(len(item["ports"]) for item in all_hosts)
            job["progress"] = 25 + int(70 * (index + 1) / max(1, len(hosts)))
            for port in host["ports"]:
                log(f"    [OPEN] {host['ip']} :{port['port']} {port['service']} {port['banner']}")
        result = {"scan_id": job_id, "target": target, "duration_s": round(time.perf_counter() - started, 2), "hosts": all_hosts}
        csv_path, json_path = export_csv(result), export_json(result)
        job.update(state="complete", phase="Complete", progress=100, result=result,
                   elapsed=result["duration_s"], csv=str(csv_path), json=str(json_path))
        HISTORY.insert(0, {"time": time.strftime("%H:%M:%S"), "target": target, "hosts": len(all_hosts), "job_id": job_id})
        del HISTORY[10:]
        log(f"[DONE] Total scan time {result['duration_s']} s | results saved: {csv_path}, {json_path}")
    except Exception as exc:
        job.update(state="error", phase="Error", error=str(exc), elapsed=round(time.perf_counter() - started, 2))


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/network")
def network():
    return jsonify(NETWORK)


@app.post("/api/scan")
def start_scan():
    data = request.get_json(silent=True) or {}
    valid, target, error = validate_target(data.get("target", NETWORK["subnet"]))
    if not valid:
        return jsonify({"error": error}), 400
    try:
        options = {"target": target, "method": data.get("method", "arp"), "ports": data.get("ports", "top100"),
                   "custom_ports": data.get("custom_ports", ""), "threads": max(1, min(int(data.get("threads", 100)), 200)),
                   "timeout": max(0.1, min(float(data.get("timeout", 0.5)), 10)), "banner": bool(data.get("banner", True)),
                   "os_guess": bool(data.get("os_guess", True))}
        parse_ports(options["ports"], options["custom_ports"])
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    job_id = uuid.uuid4().hex
    JOBS[job_id] = {"state": "running", "phase": "Starting", "progress": 0, "hosts_found": 0, "ports_found": 0,
                    "elapsed": 0, "cancel": threading.Event(), "result": None}
    threading.Thread(target=run_scan, args=(job_id, options), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.get("/api/status/<job_id>")
def status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Unknown scan job."}), 404
    return jsonify({key: job.get(key) for key in ("state", "phase", "progress", "hosts_found", "ports_found", "elapsed", "warning", "error")})


@app.get("/api/results/<job_id>")
def results(job_id):
    job = JOBS.get(job_id)
    if not job or not job.get("result"):
        return jsonify({"error": "Results are not ready."}), 404
    return jsonify(job["result"])


@app.get("/api/export/<job_id>")
def export(job_id):
    job = JOBS.get(job_id)
    fmt = request.args.get("format", "json")
    if not job or not job.get("result") or fmt not in ("csv", "json"):
        return jsonify({"error": "Export unavailable."}), 404
    path = export_csv(job["result"]) if fmt == "csv" else export_json(job["result"])
    return send_file(path, as_attachment=True)


@app.get("/api/history")
def history():
    return jsonify(HISTORY)


@app.get("/host/<ip>")
def host_detail(ip):
    for job in reversed(JOBS.values()):
        for host in (job.get("result") or {}).get("hosts", []):
            if host["ip"] == ip:
                return render_template("host.html", host=host)
    return render_template("host.html", host={"ip": ip, "ports": [], "vendor": "Unknown", "hostname": "-", "os_guess": "Unknown", "device_type": "Unknown"}), 404


if __name__ == "__main__":
    log(f"[INFO] Interface : {NETWORK['interface']}   Local IP : {NETWORK['local_ip']}   Subnet : {NETWORK['subnet']}")
    app.run(host="0.0.0.0", port=5000, debug=False)
