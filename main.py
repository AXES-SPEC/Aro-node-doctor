
#!/usr/bin/env python3

import os
import platform
import shutil
import socket
import subprocess
from datetime import datetime


def heading(title):
    print(f"\n{'=' * 45}")
    print(title)
    print('=' * 45)


def system_info():
    heading("SYSTEM INFORMATION")

    print(f"Operating system: {platform.system()}")
    print(f"Distribution: {platform.platform()}")
    print(f"Architecture: {platform.machine()}")
    print(f"Python version: {platform.python_version()}")

    try:
        with open("/proc/uptime") as file:
            uptime = float(file.readline().split()[0])
        hours = int(uptime // 3600)
        print(f"System uptime: {hours} hours")
    except Exception:
        print("System uptime: Unable to detect")


def resource_usage():
    heading("RESOURCE USAGE")

    print(f"CPU cores: {os.cpu_count() or 'Unknown'}")

    try:
        with open("/proc/meminfo") as file:
            memory = {}
            for line in file:
                key, value = line.split(":", 1)
                memory[key] = int(value.strip().split()[0])

        total = memory["MemTotal"] / 1024
        available = memory["MemAvailable"] / 1024
        used = total - available

        print(f"RAM total: {total:.0f} MB")
        print(f"RAM used: {used:.0f} MB")
        print(f"RAM usage: {(used / total) * 100:.1f}%")
    except Exception:
        print("RAM: Unable to detect")

    disk = shutil.disk_usage("/")
    used_percent = (disk.used / disk.total) * 100

    print(f"Disk total: {disk.total / (1024**3):.1f} GB")
    print(f"Disk free: {disk.free / (1024**3):.1f} GB")
    print(f"Disk usage: {used_percent:.1f}%")


def network_checks():
    heading("NETWORK DIAGNOSTICS")

    try:
        socket.create_connection(("1.1.1.1", 443), timeout=5)
        print("[PASS] Internet connectivity")
    except OSError:
        print("[FAIL] Internet connectivity")

    try:
        socket.gethostbyname("example.com")
        print("[PASS] DNS resolution")
    except OSError:
        print("[FAIL] DNS resolution")



def service_checks():
    heading("ARO SERVICE CHECKS")

    services = ["agent", "rpc"]

    if shutil.which("systemctl") is None:
        print("[SKIP] systemctl is not available")
        return

    for service in services:
        result = subprocess.run(
            ["systemctl", "show", service, "--no-page",
             "--property=LoadState,ActiveState,SubState,NRestarts"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"[FAIL] {service}: unable to inspect")
            continue

        details = dict(
            line.split("=", 1)
            for line in result.stdout.splitlines()
            if "=" in line
        )

        load = details.get("LoadState", "unknown")
        active = details.get("ActiveState", "unknown")
        sub = details.get("SubState", "unknown")
        restarts = details.get("NRestarts", "unknown")

        if load == "not-found":
            print(f"[FAIL] {service}: service not installed")
            continue

        status = "PASS" if active == "active" else "WARN"

        print(f"[{status}] {service}: {active} ({sub})")
        print(f"       Restart count: {restarts}")



def main():
    print("ARO NODE DOCTOR")
    print(f"Diagnostic date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    system_info()
    resource_usage()
    network_checks()
    service_checks()

    heading("DIAGNOSTICS COMPLETE")
    print("ARO Node Doctor finished its checks")
    print("No system configurations were modified")


if __name__ == "__main__":
    main()
