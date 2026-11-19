#!/usr/bin/env python3

import io
import os
import platform
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


def network_checks():
    heading("NETWORK DIAGNOSTICS")
    try:
        connection = socket.create_connection(("1.1.1.1", 443), timeout=5)
        connection.close()
        print("[PASS] Internet connectivity")
    except OSError:
        print("[FAIL] Internet connectivity")
        finding("CRITICAL", "Cannot connect to 1.1.1.1 on TCP port 443",
                "Check the active network connection, gateway and firewall rules")
    try:
        socket.gethostbyname("example.com")
        print("[PASS] DNS resolution")
    except OSError:
        print("[FAIL] DNS resolution")
        finding("WARNING", "DNS lookup for example.com failed",
                "Check configured DNS servers and network connection")


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
        matches = [line for line in result.stdout.splitlines()
                   if any(word in line.lower() for word in keywords)]
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
