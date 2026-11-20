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



def dns_resolver_diagnostics():
    heading("DNS RESOLVER DIAGNOSTICS")
    resolv_conf = Path("/etc/resolv.conf")
    nameservers = []
    try:
        if resolv_conf.is_symlink():
            print(f"Resolver configuration link: {os.readlink(resolv_conf)}")
        else:
            print("Resolver configuration: /etc/resolv.conf")
        for line in resolv_conf.read_text(encoding="utf-8").splitlines():
            fields = line.split("#", 1)[0].split()
            if len(fields) >= 2 and fields[0] == "nameserver":
                address = fields[1]
                if address not in nameservers:
                    nameservers.append(address)
    except OSError as error:
        print(f"[WARN] Cannot read /etc/resolv.conf: {error}")
        finding("WARNING", "Could not read /etc/resolv.conf",
                "Check resolver configuration permissions and the system DNS manager")

    if nameservers:
        print("Configured DNS server(s): " + ", ".join(nameservers))
    else:
        print("[WARN] No nameserver entries found in /etc/resolv.conf")
        finding("WARNING", "No DNS nameserver is configured in /etc/resolv.conf",
                "Check the DNS settings supplied by NetworkManager or systemd-resolved")

    if shutil.which("systemctl"):
        for service in ("systemd-resolved", "NetworkManager"):
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True, text=True, timeout=5
                )
                state = result.stdout.strip() or "inactive"
                print(f"{service}: {state}")
            except (OSError, subprocess.TimeoutExpired):
                print(f"{service}: status unavailable")

    listeners = []
    if shutil.which("ss"):
        try:
            result = subprocess.run(
                ["ss", "-H", "-lntu"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                listeners = [
                    line.strip() for line in result.stdout.splitlines()
                    if re.search(r":53\\s", line)
                ]
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        print("[INFO] ss is unavailable; local DNS listener check skipped")

    local_servers = {"127.0.0.1", "127.0.0.53", "::1"}
    configured_local = [server for server in nameservers if server in local_servers]
    if listeners:
        print("Local DNS listener(s) on port 53:")
        for listener in listeners:
            print(f"  {listener}")
    elif configured_local:
        print("[FAIL] A localhost DNS server is configured, but no listener on port 53 was detected")
        finding("WARNING", "A localhost DNS server is configured without a detected local port 53 listener",
                "Check whether systemd-resolved or another local DNS resolver is running and listening on the configured address")
    else:
        print("[INFO] No local DNS listener detected (not required for an external DNS server)")

    if shutil.which("getent"):
        try:
            result = subprocess.run(
                ["getent", "ahostsv4", "ops.aro.network"],
                capture_output=True, text=True, timeout=10
            )
            addresses = sorted({
                line.split()[0] for line in result.stdout.splitlines() if line.split()
            })
            if result.returncode == 0 and addresses:
                print("[PASS] System resolver lookup for ops.aro.network: " + ", ".join(addresses))
            else:
                print("[FAIL] System resolver could not resolve ops.aro.network")
                finding("WARNING", "System DNS lookup for ops.aro.network failed",
                        "Check the configured DNS server, resolver service and network connection")
        except (OSError, subprocess.TimeoutExpired):
            print("[WARN] System DNS lookup test could not complete")
            finding("WARNING", "System DNS lookup test could not complete",
                    "Check resolver responsiveness and retry the diagnostic")
    else:
        print("[SKIP] getent is unavailable; system resolver lookup skipped")

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



def network_interruption_tracking():
    heading("NETWORK INTERRUPTION TRACKING")
    if not shutil.which("journalctl"):
        print("[SKIP] journalctl is unavailable")
        return

    # Identify the interface carrying the default route so Docker bridges,
    # veth pairs and unrelated Wi-Fi transitions are not counted as outages.
    active_interfaces = set()
    if shutil.which("ip"):
        for args in (["ip", "-o", "route", "show", "default"],
                     ["ip", "-o", "-6", "route", "show", "default"]):
            try:
                route = subprocess.run(args, capture_output=True, text=True, timeout=5)
                for line in route.stdout.splitlines():
                    match = re.search(r"\bdev\s+(\S+)", line)
                    if match:
                        active_interfaces.add(match.group(1))
            except (OSError, subprocess.TimeoutExpired):
                pass

    if active_interfaces:
        print("Default-route interface(s): " + ", ".join(sorted(active_interfaces)))
    else:
        print("[INFO] Default-route interface could not be identified; using global NetworkManager state events only")

    sources = [
        ("NetworkManager", ["journalctl", "-u", "NetworkManager", "--since", "24 hours ago", "--no-pager", "-o", "short-iso"]),
        ("Kernel network", ["journalctl", "-k", "--since", "24 hours ago", "--no-pager", "-o", "short-iso"]),
    ]
    events = []
    source_available = 0

    for label, command in sources:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"[WARN] Could not read {label} journal")
                continue
            source_available += 1

            for line in result.stdout.splitlines():
                if not re.match(r"^\d{4}-\d{2}-\d{2}[T ]", line):
                    continue

                lower = line.lower()
                interface_match = re.search(r"device \(([^)]+)\)", line)
                interface = interface_match.group(1) if interface_match else None

                if label == "NetworkManager":
                    # Global manager state changes represent system-wide connectivity.
                    global_disconnect = "manager: networkmanager state is now disconnected" in lower
                    global_recovery = (
                        "manager: networkmanager state is now connected_global" in lower
                        or "manager: networkmanager state is now connected_site" in lower
                    )
                    # Device events count only for the active default-route interface.
                    relevant_device = (
                        interface is not None
                        and (not active_interfaces or interface in active_interfaces)
                    )
                    device_disconnect = relevant_device and (
                        "carrier: link disconnected" in lower
                        or bool(re.search(r"state change: [^\\n]*-> disconnected", lower))
                        or "state change: activated -> deactivating" in lower
                    )
                    device_recovery = relevant_device and (
                        "carrier: link connected" in lower
                        or bool(re.search(r"state change: [^\\n]*-> activated", lower))
                    )
                    is_disconnect = global_disconnect or device_disconnect
                    is_recovery = global_recovery or device_recovery
                else:
                    # Kernel messages are limited to the active uplink interface.
                    if not interface_match:
                        continue
                    relevant_device = (
                        not active_interfaces or interface in active_interfaces
                    )
                    if not relevant_device:
                        continue
                    is_disconnect = bool(re.search(
                        r"(?:link is down|link down|carrier lost|carrier off)", lower
                    ))
                    is_recovery = bool(re.search(
                        r"(?:link is up|link up|carrier acquired|carrier on)", lower
                    ))

                if is_disconnect or is_recovery:
                    events.append({
                        "source": label,
                        "interface": interface or "system",
                        "line": line,
                        "time": journal_timestamp(line),
                        "kind": "INTERRUPTION" if is_disconnect else "RECOVERY",
                    })
        except (OSError, subprocess.TimeoutExpired):
            print(f"[WARN] {label} journal query did not complete")

    if source_available == 0:
        print("[WARN] Network event journals could not be read")
        finding("WARNING", "Could not inspect NetworkManager or kernel network journals",
                "Run the diagnostic with sudo and ensure the system journal is available")
        return

    events.sort(key=lambda item: item["time"].timestamp() if item["time"] else float("-inf"))

    # Pair state transitions: ignore duplicate CONNECTED_SITE/CONNECTED_GLOBAL
    # messages and never report a recovery unless an interruption was observed.
    paired_events = []
    outage_open = False
    unmatched_recoveries = 0
    for event in events:
        if event["kind"] == "INTERRUPTION":
            if not outage_open:
                paired_events.append(event)
                outage_open = True
        elif event["kind"] == "RECOVERY":
            if outage_open:
                paired_events.append(event)
                outage_open = False
            else:
                unmatched_recoveries += 1

    interruptions = [item for item in paired_events if item["kind"] == "INTERRUPTION"]
    recoveries = [item for item in paired_events if item["kind"] == "RECOVERY"]
    print(f"[INFO] Confirmed uplink interruption events (24h): {len(interruptions)}")
    print(f"[INFO] Matched uplink recovery events (24h): {len(recoveries)}")
    if unmatched_recoveries:
        print(f"[INFO] Unmatched/duplicate recovery messages ignored: {unmatched_recoveries}")
    if outage_open:
        print("[WARNING] An uplink interruption has no matching recovery event")
        finding("WARNING", "An uplink interruption has no matching recovery event in the last 24 hours",
                "Check the latest network event and current connectivity")

    if paired_events:
        print("UPLINK EVENT TIMELINE (latest 12 events):")
        for event in paired_events[-12:]:
            timestamp = (
                event["time"].astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
                if event["time"] else "time unavailable"
            )
            detail = event["line"].split(": ", 1)[-1]
            print(f"  [{timestamp}] [{event['source']}] [{event['interface']}] {event['kind']}: {detail}")
    else:
        print("[PASS] No complete uplink interruption/recovery pairs found in the last 24 hours")

    if interruptions:
        finding("WARNING", f"Found {len(interruptions)} default-route network interruption event(s) in the last 24 hours",
                "Compare these timestamps with the RPC failure timeline; a link transition does not always mean the entire internet connection was unavailable")

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
                 "--property=LoadState,ActiveState,SubState,NRestarts,ActiveEnterTimestamp"],
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
            timestamp = details.get("ActiveEnterTimestamp", "")
            match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", timestamp)
            if match:
                try:
                    started = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
                    elapsed = datetime.now() - started
                    seconds = max(0, int(elapsed.total_seconds()))
                    days, remainder = divmod(seconds, 86400)
                    hours, remainder = divmod(remainder, 3600)
                    minutes = remainder // 60
                    uptime = f"{days}d {hours}h {minutes}m" if days else f"{hours}h {minutes}m"
                    print(f"       Service uptime: {uptime}")
                except ValueError:
                    print("       Service uptime: Unable to parse systemd timestamp")
            else:
                print("       Service uptime: Not available")
        print(f"       Restart count (systemd): {restarts}")
        try:
            if int(restarts) > 0:
                print("       [INFO] Restart count is historical; recent log events determine whether it needs attention")
        except ValueError:
            pass


def journal_timestamp(line):
    """Parse the timestamp at the start of a journal short-iso line."""
    match = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\\d{2}:\\d{2}|Z)?)",
        line
    )
    if not match:
        return None
    try:
        return datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
    except ValueError:
        return None


def format_duration(seconds):
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def log_analysis():
    heading("ARO LOG ANALYSIS")
    if shutil.which("journalctl") is None:
        print("[SKIP] journalctl is not available")
        finding("WARNING", "journalctl is unavailable", "Use a systemd-based Linux system to inspect service logs")
        return

    for service in ["agent", "rpc"]:
        print(f"\nChecking {service} logs (last 24 hours)...")
        command = ["journalctl", "-u", service, "--since", "24 hours ago",
                   "--no-pager", "-o", "short-iso"]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=30
            )
            # journalctl may print informational text even when no journal
            # entries are visible. Only timestamped output lines count as entries.
            has_entries = any(
                re.match(r"^\d{4}-\d{2}-\d{2}[T ]", line)
                for line in result.stdout.splitlines()
            )
            # Retry with non-interactive sudo when no actual entries are visible.
            if result.returncode == 0 and not has_entries and shutil.which("sudo"):
                privileged = subprocess.run(
                    ["sudo", "-n"] + command,
                    capture_output=True, text=True, timeout=30
                )
                privileged_has_entries = any(
                    re.match(r"^\d{4}-\d{2}-\d{2}[T ]", line)
                    for line in privileged.stdout.splitlines()
                )
                if privileged.returncode == 0 and privileged_has_entries:
                    result = privileged
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is None or result.returncode != 0:
            print(f"[WARN] Unable to read {service} logs")
            finding("WARNING", f"Could not read {service} logs",
                    "Check journal permissions; run the diagnostic with sudo if needed")
            continue

        # Ignore journalctl notices such as "-- No entries --"; only
        # timestamped journal records are valid input for log analysis.
        log_lines = [
            line for line in result.stdout.splitlines()
            if re.match(r"^\d{4}-\d{2}-\d{2}[T ]", line)
        ]
        if not log_lines:
            print(f"[WARN] No readable {service} journal entries were returned")
            finding("WARNING", f"Could not access readable {service} journal entries",
                    "Run the diagnostic with sudo (sudo python3 main.py) or grant the user access to the systemd journal")
            continue

        if service == "rpc":
            login_successes = [
                line for line in log_lines
                if "login to server success" in line.lower()
            ]
            proxy_successes = [
                line for line in log_lines
                if "start proxy success" in line.lower()
            ]

            failures = []
            for line in log_lines:
                lower = line.lower()
                if not any(word in lower for word in
                           ("timeout", "connection refused", "network is unreachable")):
                    continue
                if "lookup ops.aro.network" in lower:
                    category = "DNS"
                elif "dial tcp" in lower:
                    category = "TCP"
                else:
                    continue
                failures.append({
                    "line": line,
                    "time": journal_timestamp(line),
                    "category": category,
                })

            dns_count = sum(item["category"] == "DNS" for item in failures)
            tcp_count = sum(item["category"] == "TCP" for item in failures)
            success_events = [
                {"line": line, "time": journal_timestamp(line)}
                for line in proxy_successes
            ]
            success_events = [item for item in success_events if item["time"] is not None]

            print(f"[INFO] RPC DNS failures (24h): {dns_count}")
            print(f"[INFO] RPC TCP failures (24h, excluding DNS lookup errors): {tcp_count}")
            print(f"[INFO] Successful server logins (24h): {len(login_successes)}")
            print(f"[INFO] Successful proxy starts (24h): {len(proxy_successes)}")

            # Group repeated retries into one incident when failures are no
            # more than ten minutes apart. This avoids treating every retry
            # as a separate outage.
            episodes = []
            for event in failures:
                event_time = event["time"]
                if not episodes or event_time is None or episodes[-1]["last_time"] is None:
                    episodes.append({
                        "first_time": event_time,
                        "last_time": event_time,
                        "events": [event],
                    })
                    continue
                gap = (event_time - episodes[-1]["last_time"]).total_seconds()
                if 0 <= gap <= 600:
                    episodes[-1]["last_time"] = event_time
                    episodes[-1]["events"].append(event)
                else:
                    episodes.append({
                        "first_time": event_time,
                        "last_time": event_time,
                        "events": [event],
                    })

            recovered_episodes = []
            unresolved_episodes = []
            for episode in episodes:
                recovery = next(
                    (item for item in success_events
                     if episode["last_time"] is not None and item["time"] > episode["last_time"]),
                    None
                )
                episode["recovery"] = recovery
                if recovery and episode["first_time"] is not None:
                    episode["duration"] = (
                        recovery["time"] - episode["first_time"]
                    ).total_seconds()
                    recovered_episodes.append(episode)
                else:
                    episode["duration"] = None
                    unresolved_episodes.append(episode)

            print(f"[INFO] Connection incident groups (10-minute grouping): {len(episodes)}")
            print(f"[INFO] Incidents followed by proxy recovery: {len(recovered_episodes)}")
            print(f"[INFO] Incidents without a later proxy recovery: {len(unresolved_episodes)}")

            durations = [episode["duration"] for episode in recovered_episodes]
            if durations:
                average = sum(durations) / len(durations)
                print(f"[INFO] Average incident-to-proxy-recovery time: {format_duration(average)}")
                print(f"[INFO] Longest incident-to-proxy-recovery time: {format_duration(max(durations))}")
            else:
                print("[INFO] Recovery duration unavailable; no timestamped recovered incidents found")

            if failures:
                print("\nRPC FAILURE TIMELINE (latest 10 events):")
                for event in failures[-10:]:
                    timestamp = event["time"].astimezone().strftime("%Y-%m-%d %H:%M:%S %Z") if event["time"] else "time unavailable"
                    detail = event["line"].split(": ", 1)[-1]
                    print(f"  [{timestamp}] {event['category']}: {detail}")

                print("\nRPC INCIDENT SUMMARY:")
                for index, episode in enumerate(episodes[-10:], 1):
                    first = episode["first_time"]
                    last = episode["last_time"]
                    first_text = first.astimezone().strftime("%m-%d %H:%M:%S") if first else "unknown"
                    last_text = last.astimezone().strftime("%H:%M:%S") if last else "unknown"
                    categories = sorted({event["category"] for event in episode["events"]})
                    label = "/".join(categories)
                    if episode["recovery"]:
                        recovered_at = episode["recovery"]["time"].astimezone().strftime("%H:%M:%S")
                        duration = format_duration(episode["duration"])
                        print(f"  {index}. {first_text}–{last_text} ({label}, {len(episode['events'])} failures) -> proxy recovered {recovered_at} ({duration})")
                    else:
                        print(f"  {index}. {first_text}–{last_text} ({label}, {len(episode['events'])} failures) -> no later proxy recovery found")

                finding("WARNING", f"RPC recorded {len(failures)} connection failures across {len(episodes)} incident group(s) in the last 24 hours",
                        "Review the failure timeline and incident durations; investigate repeated DNS lookup timeouts and TCP timeouts even if the proxy later recovers")
            elif login_successes and proxy_successes:
                print("[PASS] RPC logs show successful login and proxy startup, with no detected DNS/TCP connection failures")
            else:
                print("[INFO] No matching RPC connection or recovery events found in the last 24 hours; this is not proof of a failure")
            continue

        keywords = ["error", "failed", "failure", "critical", "warning"]
        matches = [line for line in log_lines
                   if any(word in line.lower() for word in keywords)]
        if not matches:
            print("[PASS] No diagnostic keywords found in agent logs during the last 24 hours")
            continue
        print(f"[WARN] Found {len(matches)} agent log entries containing diagnostic keywords")
        for line in matches[-10:]:
            print(f"  {line}")
        finding("WARNING", f"Agent logs contain {len(matches)} entries with diagnostic keywords in the last 24 hours",
                "Review the displayed agent entries; keyword matches may include harmless messages")


def historical_report_comparison(current_report):
    """Compare this run with the most recent report saved before this run."""
    report_dir = Path("reports")
    previous_reports = sorted(
        report_dir.glob("aro-report-*.txt"),
        key=lambda path: path.name,
        reverse=True
    )
    if not previous_reports:
        heading("HISTORICAL REPORT COMPARISON")
        print("[INFO] No earlier report found; future runs will be compared here")
        return

    previous_path = previous_reports[0]
    try:
        previous = previous_path.read_text(encoding="utf-8")
    except OSError as error:
        heading("HISTORICAL REPORT COMPARISON")
        print(f"[WARN] Could not read previous report: {error}")
        return

    def metric(content, pattern):
        match = re.search(pattern, content, re.IGNORECASE)
        return match.group(1).strip() if match else "not recorded"

    heading("HISTORICAL REPORT COMPARISON")
    print(f"Previous report: {previous_path.name}")
    fields = [
        ("Overall status", r"Overall status:\s*(.+)"),
        ("Warnings", r"Warnings:\s*(\d+)"),
        ("RPC DNS failures", r"RPC DNS failures \(24h\):\s*(\d+)"),
        ("RPC TCP failures", r"RPC TCP failures \(24h[^)]*\):\s*(\d+)"),
        ("RPC incident groups", r"Connection incident groups \(10-minute grouping\):\s*(\d+)"),
        ("Uplink interruptions", r"Confirmed uplink interruption events \(24h\):\s*(\d+)"),
    ]
    for label, pattern in fields:
        old_value = metric(previous, pattern)
        new_value = metric(current_report, pattern)
        change = ""
        if old_value.isdigit() and new_value.isdigit():
            delta = int(new_value) - int(old_value)
            change = f" ({delta:+d})"
        print(f"{label}: {old_value} -> {new_value}{change}")


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
        dns_resolver_diagnostics()
        network_interruption_tracking()
        service_checks()
        log_analysis()
        historical_report_comparison(output.getvalue())
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
