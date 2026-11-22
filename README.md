# ARO Node Doctor

A lightweight, read-only diagnostic tool for ARO Network node operators running Linux

ARO Node Doctor checks the host system, network connectivity, DNS resolution, ARO services, and recent service logs. It produces a health assessment and saves a timestamped report for later comparison

## Features

### System health
- Operating system, architecture, Python version, and system uptime
- CPU load, RAM usage, root disk usage, and available thermal readings
- Configurable warning and critical thresholds built into the diagnostic checks

### Network and DNS
- Separate IPv4 and IPv6 internet connectivity checks
- DNS resolution for `ops.aro.network`
- TCP reachability checks for ARO port `30071` and HTTPS port `443`
- DNS resolver configuration and local listener checks
- Current default-route and physical uplink event tracking to help identify interruptions, including after an interface change

### ARO services and logs
- `agent` and `rpc` systemd service status and uptime
- Historical systemd restart counts
- Last 24 hours of agent and RPC journal logs
- RPC DNS and TCP connection failure counts
- Grouped RPC incidents, successful proxy recoveries, and recovery durations

### Reports
- Overall health assessment with findings and recommendations
- Timestamped text reports saved in the `reports/` directory
- Comparison with the most recent previous report

## Requirements

- Linux with systemd
- Python 3.9 or newer
- ARO node services named `agent` and `rpc`
- Common system utilities: `ip`, `ping`, `ss`, `getent`, and `journalctl`

Some checks are skipped when their required system utility or data source is unavailable

## Installation

Clone the repository:

```bash
git clone https://github.com/AXES-SPEC/Aro-node-doctor.git
cd Aro-node-doctor
```

## Run

Run with sudo to allow access to system and service journal logs:

```bash
sudo python3 main.py
```

The tool does not require third-party Python packages

Reports are written to:

```
reports/aro-report-YYYYMMDD-HHMMSS.txt
```

Run the command again later to compare the latest diagnostic results with the previous saved report

## Update

Pull the latest version from GitHub:

```bash
git pull
```

## Safety and limitations

ARO Node Doctor does not modify system or ARO node configuration. It does create a local `reports/` directory and save diagnostic report files. It does not restart services, edit configuration files, change firewall rules, or tune the node

Results are diagnostic indicators, not a guarantee of node performance, uptime, or ARO rewards. Network conditions and journal availability can affect the results

## Project status

Under active development. Feedback, bug reports, and contributions are welcome

## Disclaimer

ARO Node Doctor is an independent community project and is not an official ARO Network product
