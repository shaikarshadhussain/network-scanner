# Network Scanner

A Flask-based network discovery and port-scanning dashboard for inspecting devices on a local network.

## Features

- Discover hosts with ARP or ICMP sweeps
- Scan selected or custom TCP ports
- Grab service banners
- Estimate device type and operating system
- View scan progress and results in a browser dashboard
- Export results as JSON or CSV

## Requirements

- Python 3.10 or newer
- A local network interface
- Administrator/root privileges may be required for some Scapy discovery methods

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Run

```powershell
python app.py
```

Open <http://127.0.0.1:5000> in a browser.

On this machine, the configured interpreter can also be used directly:

```powershell
E:/Python/python.exe app.py
```

## Notes

Only scan networks and systems that you own or have explicit permission to test. Scan results are written to the local `reports/` directory and are not committed to Git.

## Project layout

```text
app.py              Flask application and scan job manager
scanner/            Discovery, port scanning, fingerprinting, and reporting modules
templates/          Dashboard HTML templates
static/             Dashboard CSS and JavaScript
data/               Local service and vendor lookup data
reports/            Generated scan reports (ignored by Git)
```
