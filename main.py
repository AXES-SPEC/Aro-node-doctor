#!/usr/bin/env python3

import io
import os
import platform
import re
import shutil
import socket
import subprocess
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

FINDINGS = []


def heading(title):
    print(f"\n{'=' * 45}")
    print(title)
    print('=' * 45)


def finding(severity, message, recommendation):
    FINDINGS.append({"severity": severity, "message": message, "recommendation": recommendation})


def check_threshold(value, warning_at, critical_at, label, recommendation):
    if value >= critical_at:
        finding("CRITICAL", f"{label} is {value:.1f}%", recommendation)
    elif value >= warning_at:
        finding("WARNING", f"{label} is {value:.1f}%", recommendation)


def system_info():
    heading("SYSTEM INFORMATION")
    print(f"Operating system: {platform.system()}")
    print(f"Distribution: {platform.platform()}")
    print(f"Architecture: {platform.machine()}")
    print(f"Python version: {platform.python_version()}")
    try:
        with open("/proc/uptime", encoding="utf-8") as file:
            uptime = float(file.readline().split()[0])
        print(f"System uptime: {int(uptime // 3600)} hours")
    except (OSError, ValueError, IndexError):
        print("System uptime: Unable to detect")


def resource_usage():
    heading("RESOURCE USAGE")
    cpu_count = os.cpu_count() or 1
    print(f"CPU cores: {cpu_count}")
    try:
        load_1, load_5, load_15 = os.getloadavg()
        print(f"CPU load average (1/5/15 min): {load_1:.2f} / {load_5:.2f} / {load_15:.2f}")
        ratio = load_1 / cpu_count
        if ratio >= 2:
            finding("CRITICAL", f"1-minute load is {ratio:.2f} times the CPU core count",
                    "Check CPU-heavy processes and investigate sustained system load")
        elif ratio >= 1:
            finding("WARNING", f"1-minute load is {ratio:.2f} times the CPU core count",
                    "Review running processes if high load persists")
    except (OSError, AttributeError):
        print("CPU load average: Unable to detect")

    try:
        memory = {}
        with open("/proc/meminfo", encoding="utf-8") as file:
            for line in file:
                key, value = line.split(":", 1)
                memory[key] = int(value.strip().split()[0])
        total = memory["MemTotal"] / 1024
        available = memory["MemAvailable"] / 1024
        used = total - available
        percent = (used / total) * 100 if total else 0
        print(f"RAM total: {total:.0f} MB")
        print(f"RAM used: {used:.0f} MB")
        print(f"RAM usage: {percent:.1f}%")
        check_threshold(percent, 85, 95, "RAM usage",
                        "Check memory-heavy processes and consider reducing workload")
    except (OSError, KeyError, ValueError, ZeroDivisionError):
        print("RAM: Unable to detect")

    try:
        disk = shutil.disk_usage("/")
        percent = (disk.used / disk.total) * 100 if disk.total else 0
        print(f"Disk total: {disk.total / (1024**3):.1f} GB")
        print(f"Disk free: {disk.free / (1024**3):.1f} GB")
        print(f"Disk usage: {percent:.1f}%")
        check_threshold(percent, 85, 95, "Root disk usage",
                        "Free disk space; inspect large logs and unused files before deleting anything")
    except OSError:
        print("Disk usage: Unable to detect")
    check_cpu_temperature()


def check_cpu_temperature():
    readings = []
    for sensor in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            raw = int(sensor.read_text(encoding="utf-8").strip())
            temperature = raw / 1000 if raw > 1000 else float(raw)
            if -20 <= temperature <= 150:
                readings.append(temperature)
        except (OSError, ValueError):
            continue
    if not readings:
        print("CPU temperature: Not available (sensor not exposed)")
        return
    hottest = max(readings)
    print(f"Highest thermal sensor reading: {hottest:.1f} °C")
    if hottest >= 90:
        finding("CRITICAL", f"Thermal sensor reading is {hottest:.1f} °C",
                "Check cooling and airflow; shut down if the device is overheating")
    elif hottest >= 80:
        finding("WARNING", f"Thermal sensor reading is {hottest:.1f} °C",
                "Check ventilation and monitor temperatures under load")


def ping_diagnostics(label, family_flag, target):
    if shutil.which("ping") is None:
        print(f"[SKIP] {label} packet-loss test: ping is unavailable")
        return
    try:
        result = subprocess.run(
            ["ping", family_flag, "-c", "5", "-W", "3", target],
            capture_output=True, text=True, timeout=20
        )
    except (OSError, subprocess.TimeoutExpired):
        print(f"[WARN] {label} ping test could not complete")
        finding("WARNING", f"{label} ping test could not complete",
                "Check network connectivity and retry the diagnostic")
        return

    output = result.stdout + result.stderr
    loss_match = re.search(r"([0-9.]+)% packet loss", output)
    rtt_match = re.search(
        r"(?:round-trip|rtt) min/avg/max(?:/mdev)? = [0-9.]+/([0-9.]+)/", output
    )
    if loss_match:
        loss = float(loss_match.group(1))
        latency = float(rtt_match.group(1)) if rtt_match else None
        latency_text = f", average latency {latency:.1f} ms" if latency is not None else ""
        print(f"[INFO] {label}: {loss:.1f}% packet loss{latency_text}")
        if loss >= 50:
            finding("CRITICAL", f"{label} packet loss is {loss:.1f}%",
                    "Check the network link, mobile signal, routing and firewall")
        elif loss > 0:
            finding("WARNING", f"{label} packet loss is {loss:.1f}%",
                    "Monitor connection quality and check for intermittent network issues")
        if latency is not None and latency >= 1000:
            finding("WARNING", f"{label} average ping latency is {latency:.1f} ms",
                    "Check network congestion and signal quality")
    else:
        print(f"[WARN] {label} ping result could not be interpreted")


def tcp_probe(label, family, sockaddr, port):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(8)
    started = datetime.now().timestamp()
    try:
        sock.connect((sockaddr[0], port) if family == socket.AF_INET else
                     (sockaddr[0], port, sockaddr[2], sockaddr[3]))
        latency = (datetime.now().timestamp() - started) * 1000
        print(f"[PASS] {label}: TCP port {port} reachable ({latency:.1f} ms)")
        if latency >= 1000:
            finding("WARNING", f"{label} connection latency is {latency:.1f} ms",
                    "Check network congestion, routing and mobile signal")
        return True
    except OSError as error:
        print(f"[FAIL] {label}: TCP port {port} unavailable ({error})")
        return False
    finally:
        sock.close()


def network_checks():
    heading("NETWORK DIAGNOSTICS")

    # Test general IPv4 and IPv6 reachability independently
    ping_diagnostics("IPv4 internet", "-4", "1.1.1.1")
    ping_diagnostics("IPv6 internet", "-6", "2606:4700:4700::1111")

    # DNS resolution for the ARO endpoint, separated by address family
    aro_host = "ops.aro.network"
    resolved = {socket.AF_INET: [], socket.AF_INET6: []}
    for family, label in [(socket.AF_INET, "IPv4"), (socket.AF_INET6, "IPv6")]:
        try:
            records = socket.getaddrinfo(aro_host, 30071, family, socket.SOCK_STREAM)
            seen = set()
            for record in records:
                address = record[4]
                if address[0] not in seen:
                    resolved[family].append(address)
                    seen.add(address[0])
            addresses = ", ".join(item[0] for item in resolved[family])
            print(f"[PASS] {label} DNS for {aro_host}: {addresses}")
        except socket.gaierror:
            print(f"[INFO] No {label} DNS address returned for {aro_host}")

    if not resolved[socket.AF_INET] and not resolved[socket.AF_INET6]:
        finding("CRITICAL", f"DNS could not resolve {aro_host} to IPv4 or IPv6",
                "Check DNS servers and network connectivity")

    # Verify ARO's actual FRPC server port on every resolved address.
    # A failure on one IP family is a warning when the other family works.
    aro_reachability = {}
    if not resolved[socket.AF_INET] and not resolved[socket.AF_INET6]:
        print("[SKIP] ARO server port test: hostname did not resolve")
    else:
        for family, label in [(socket.AF_INET, "ARO IPv4"), (socket.AF_INET6, "ARO IPv6")]:
            addresses = resolved[family]
            if not addresses:
                print(f"[SKIP] {label}: no DNS address available")
                aro_reachability[family] = None
                continue
            successes = 0
            for address in addresses:
                if tcp_probe(label + " " + address[0], family, address, 30071):
                    successes += 1
            aro_reachability[family] = successes > 0

        any_aro_path_works = any(value is True for value in aro_reachability.values())
        for family, label in [(socket.AF_INET, "IPv4"), (socket.AF_INET6, "IPv6")]:
            if aro_reachability.get(family) is False:
                severity = "WARNING" if any_aro_path_works else "CRITICAL"
                finding(severity, f"ARO server port 30071 is unreachable over {label}",
                        "Check this IP family's routing and firewall; another working IP family may still keep ARO connected")

    # General HTTPS reachability tests distinguish internet access from ARO access
    for family, label, sockaddr in [
        (socket.AF_INET, "IPv4 internet TCP", ("1.1.1.1",)),
        (socket.AF_INET6, "IPv6 internet TCP", ("2606:4700:4700::1111", 0, 0, 0)),
    ]:
        if not tcp_probe(label, family, sockaddr, 443):
            finding("WARNING", f"{label} on port 443 failed",
                    "Check connectivity for this IP version and the network firewall")


def service_checks():
    heading("ARO SERVICE CHECKS")
    if shutil.which("systemctl") is None:
        print("[SKIP] systemctl is not available")
        finding("WARNING", "systemctl is unavailable",
                "Run this tool on a systemd-based Linux distribution")
        return
    for service in ["agent", "rpc"]:
        try:
            result = subprocess.run(
                ["systemctl", "show", service, "--no-page",
                 "--property=LoadState,ActiveState,SubState,NRestarts"],
                capture_output=True, text=True, timeout=10
            )
        except (OSError, subprocess.TimeoutExpired):
            print(f"[WARN] {service}: unable to inspect")
            finding("WARNING", f"Could not inspect {service}",
                    "Check systemd availability and permissions")
            continue
        if result.returncode != 0:
            print(f"[WARN] {service}: unable to inspect")
            finding("WARNING", f"Could not inspect {service}",
                    "Check systemd availability and permissions")
            continue
        details = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        load = details.get("LoadState", "unknown")
        active = details.get("ActiveState", "unknown")
        sub = details.get("SubState", "unknown")
        restarts = details.get("NRestarts", "unknown")
        if load == "not-found":
            print(f"[FAIL] {service}: service not installed")
            finding("CRITICAL", f"ARO {service} service is not installed",
                    "Verify the ARO installation and service unit name")
            continue
        if active != "active":
            print(f"[FAIL] {service}: {active} ({sub})")
            finding("CRITICAL", f"ARO {service} service is {active} ({sub})",
                    f"Inspect {service} logs and configuration before attempting a restart")
        else:
            print(f"[PASS] {service}: {active} ({sub})")
        print(f"       Restart count: {restarts}")
        try:
            if int(restarts) > 0:
                finding("WARNING", f"{service} has restarted {restarts} time(s) since systemd began tracking it",
                        f"Review recent {service} logs for recurring issues")
        except ValueError:
            pass


def log_analysis():
    heading("ARO LOG ANALYSIS")
    if shutil.which("journalctl") is None:
        print("[SKIP] journalctl is not available")
        finding("WARNING", "journalctl is unavailable", "Use a systemd-based Linux system to inspect service logs")
        return
    keywords = ["error", "failed", "failure", "critical", "warning"]
    for service in ["agent", "rpc"]:
        print(f"\nChecking {service} logs...")
        try:
            result = subprocess.run(
                ["journalctl", "-u", service, "-n", "100", "--no-pager", "-o", "cat"],
                capture_output=True, text=True, timeout=15
            )
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is None or result.returncode != 0:
            print(f"[WARN] Unable to read {service} logs")
            finding("WARNING", f"Could not read {service} logs",
                    "Check journal permissions; appropriate privileges may be required")
            continue
        log_lines = result.stdout.splitlines()
        matches = [line for line in log_lines
                   if any(word in line.lower() for word in keywords)]

        if service == "rpc":
            dns_errors = [line for line in log_lines if
                          ("lookup ops.aro.network" in line.lower() and
                           ("timeout" in line.lower() or "connection refused" in line.lower()))]
            tcp_errors = [line for line in log_lines if
                          ("dial tcp" in line.lower() and
                           ("timeout" in line.lower() or "connection refused" in line.lower()))]
            login_successes = [line for line in log_lines if "login to server success" in line.lower()]
            proxy_successes = [line for line in log_lines if "start proxy success" in line.lower()]

            print(f"[INFO] RPC DNS failures in last 100 entries: {len(dns_errors)}")
            print(f"[INFO] RPC TCP connection failures in last 100 entries: {len(tcp_errors)}")
            print(f"[INFO] Successful server logins: {len(login_successes)}")
            print(f"[INFO] Successful proxy starts: {len(proxy_successes)}")

            if dns_errors or tcp_errors:
                if login_successes and proxy_successes:
                    finding("WARNING", "RPC has experienced connection failures but also recovered successfully",
                            "Monitor DNS and TCP stability; inspect timestamps to see whether failures are becoming more frequent")
                else:
                    finding("WARNING", "RPC connection failures were found without a successful recovery in the inspected log window",
                            "Check DNS resolution, routing and TCP access to ops.aro.network:30071")
            elif login_successes and proxy_successes:
                print("[PASS] RPC logs show successful server login and proxy startup, with no matching connection failures")
            elif not matches:
                print("[PASS] No matching RPC error keywords found in the last 100 entries")

            for line in matches[-10:]:
                print(f"  {line}")
            continue

        if not matches:
            print("[PASS] No matching keywords found in the last 100 entries")
            continue
        print(f"[WARN] Found {len(matches)} log entries containing diagnostic keywords")
        for line in matches[-10:]:
            print(f"  {line}")
        finding("WARNING", f"{service} logs contain {len(matches)} entries with diagnostic keywords",
                f"Review the displayed {service} entries; keyword matches may include harmless messages")


def health_summary():
    heading("HEALTH ASSESSMENT")
    critical = sum(item["severity"] == "CRITICAL" for item in FINDINGS)
    warnings = sum(item["severity"] == "WARNING" for item in FINDINGS)
    status = "CRITICAL" if critical else "WARNING" if warnings else "HEALTHY"
    print(f"Overall status: {status}")
    print(f"Critical findings: {critical}")
    print(f"Warnings: {warnings}")
    if not FINDINGS:
        print("No issues were detected by the available checks")
        return
    heading("FINDINGS AND RECOMMENDATIONS")
    for item in FINDINGS:
        print(f"[{item['severity']}] {item['message']}")
        print(f"  Recommendation: {item['recommendation']}")


def main():
    FINDINGS.clear()
    output = io.StringIO()
    with redirect_stdout(output):
        print("ARO NODE DOCTOR")
        print(f"Diagnostic date: {datetime.now().astimezone().isoformat(timespec='seconds')}")
        system_info()
        resource_usage()
        network_checks()
        service_checks()
        log_analysis()
        health_summary()
        heading("DIAGNOSTICS COMPLETE")
        print("Read-only mode: no system configurations or services were modified")
    report = output.getvalue()
    print(report)
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)
    filename = datetime.now().strftime("aro-report-%Y%m%d-%H%M%S.txt")
    report_path = report_dir / filename
    report_path.write_text(report, encoding="utf-8")
    print(f"Diagnostic report saved: {report_path}")


if __name__ == "__main__":
    main()
