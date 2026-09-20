"""NETRA v0.1 — Network Reconnaissance Toolkit (TCP Port Scanner & Service Detection)."""
from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass
import socket, ssl, sys, threading, time
from typing import Callable, Optional

__version__ = "0.1.0"

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}
QUICK_PORTS = list(SERVICE_MAP)
DEFAULT_TIMEOUT, DEFAULT_WORKERS = 0.5, 50


# ============================================================================
# Result Models
# ============================================================================

@dataclass
class ScanResult:
    """Individual TCP port scan result."""
    port: int
    state: str
    service: str
    latency: Optional[float] = None
    banner: Optional[str] = None

    @property
    def is_open(self) -> bool: return self.state == "OPEN"
    @property
    def latency_ms(self) -> Optional[float]: return self.latency


@dataclass
class ScanResultSet:
    """Collection of port scan results with summary properties."""
    results: list[ScanResult]
    completed: int
    total: int
    interrupted: bool = False

    def __len__(self) -> int: return len(self.results)
    def __iter__(self): return iter(self.results)
    @property
    def open_ports(self) -> list[ScanResult]: return [r for r in self.results if r.is_open]


# ============================================================================
# Service Identification & Protocol-Aware Banner Detection
# ============================================================================

def clean_banner(data: bytes | str | None, max_len: int = 80) -> Optional[str]:
    """Sanitize raw banner bytes into a single trimmed display string."""
    if not data: return None
    txt = data.decode(errors="ignore") if isinstance(data, (bytes, bytearray)) else str(data)
    lines = [l.strip() for l in txt.replace("\x00", "").splitlines() if l.strip()]
    if not lines: return None
    first = lines[0]
    if first.upper().startswith("HTTP/"):
        server_line = next((l for l in lines[1:] if l.lower().startswith("server:")), None)
        if server_line:
            srv = server_line.split(":", 1)[1].strip()
            if srv:
                first = f"{first} [Server: {srv}]"
    return (first[:max_len - 3] + "..." if len(first) > max_len else first)


def detect_service(target: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> tuple[str, Optional[str]]:
    """Probe an open port for banner and identify HTTP, HTTPS, or SSH/FTP/SMTP services."""
    service, banner = SERVICE_MAP.get(port) or "UNKNOWN", None
    if service == "UNKNOWN":
        try: service = socket.getservbyport(port, "tcp").upper()
        except OSError: pass
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (443, 8443) or "HTTPS" in service:
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                with ctx.wrap_socket(s, server_hostname=target) as tls:
                    tls.sendall(f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: NETRA/1.0\r\nConnection: close\r\n\r\n".encode())
                    banner, service = clean_banner(tls.recv(1024)), "HTTPS"
            elif port in (21, 22, 25, 110, 143):
                banner = clean_banner(s.recv(1024))
                if port == 22: service = "SSH"
                elif port == 21: service = "FTP"
                elif port == 25: service = "SMTP"
            else:
                s.sendall(f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: NETRA/1.0\r\nConnection: close\r\n\r\n".encode())
                raw_data = s.recv(1024)
                if raw_data:
                    b_clean = clean_banner(raw_data)
                    if b_clean and "HTTP/" in b_clean.upper():
                        banner, service = b_clean, "HTTP"
                    elif not banner:
                        banner = b_clean
    except (OSError, ssl.SSLError): pass
    return service, banner

detect_service_and_banner = detect_service

# ============================================================================
# Core TCP Port Scanner
# ============================================================================

def normalize_target(target: str) -> str:
    """Normalize input into a raw hostname or IP address (stripping schemes, paths, and query fragments)."""
    raw = target.strip()
    for scheme in ("http://", "https://", "ftp://", "ssh://"):
        if raw.lower().startswith(scheme):
            raw = raw[len(scheme):]
            break
    return raw.partition("/")[0].partition("?")[0].partition("#")[0].strip()


class PortScanner:
    """TCP Port Scanner supporting threaded and sequential scanning."""
    def __init__(self, target: str, timeout: float = DEFAULT_TIMEOUT, workers: int = DEFAULT_WORKERS):
        cleaned = normalize_target(target)
        if not cleaned: raise ValueError("Target cannot be empty.")
        self.target, self.timeout, self.workers = cleaned, max(0.01, float(timeout)), max(1, int(workers))

    def resolve_target(self) -> str:
        """Resolve the target hostname to an IPv4 address."""
        try: return socket.gethostbyname(self.target)
        except socket.gaierror as e: raise ValueError(f"Could not resolve '{self.target}': {e}") from e

    def scan_port(self, port: int, detect_services: bool = True, stop_event: Optional[threading.Event] = None) -> Optional[ScanResult]:
        """Scan a single TCP port and detect service/banner only if port is OPEN."""
        if stop_event and stop_event.is_set(): return None
        start, state = time.perf_counter(), "ERROR"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            try:
                sock.connect((self.target, port))
                state = "OPEN"
            except (ConnectionRefusedError, ConnectionResetError): state = "CLOSED"
            except socket.timeout: state = "NO RESPONSE"
            except OSError: state = "ERROR"
        latency = (time.perf_counter() - start) * 1000.0
        service, banner = SERVICE_MAP.get(port, "UNKNOWN"), None
        if state == "OPEN" and detect_services and not (stop_event and stop_event.is_set()):
            service, banner = detect_service(self.target, port, self.timeout)
        return ScanResult(port, state, service, latency, banner)

    def scan_sequential(self, ports: list[int], detect_services: bool = True, progress_cb: Optional[Callable] = None, stop_event: Optional[threading.Event] = None) -> ScanResultSet:
        """Scan ports sequentially on the calling thread."""
        stop_event, results = stop_event or threading.Event(), []
        for p in ports:
            if stop_event.is_set() or (r := self.scan_port(p, detect_services, stop_event)) is None: break
            results.append(r)
            if progress_cb: progress_cb(len(results), len(ports), r)
        return ScanResultSet(results, len(results), len(ports), stop_event.is_set())

    def scan_threaded(self, ports: list[int], detect_services: bool = True, progress_cb: Optional[Callable] = None, stop_event: Optional[threading.Event] = None) -> ScanResultSet:
        """Scan ports concurrently with bounded thread pool and responsive Ctrl+C handling."""
        stop_event, total, results = stop_event or threading.Event(), len(ports), []
        if not total: return ScanResultSet([], 0, 0, False)
        workers, port_iter, active = min(self.workers, total), iter(ports), {}
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        def refill():
            while len(active) < min(total, workers * 2) and not stop_event.is_set():
                try: active[ex.submit(self.scan_port, next(port_iter), detect_services, stop_event)] = 1
                except StopIteration: break
        refill()
        try:
            while active and not stop_event.is_set():
                try: done, _ = concurrent.futures.wait(active.keys(), timeout=0.05, return_when=concurrent.futures.FIRST_COMPLETED)
                except KeyboardInterrupt: stop_event.set(); break
                for fut in done:
                    active.pop(fut)
                    if not fut.cancelled() and (res := fut.result()):
                        results.append(res)
                        if progress_cb and not stop_event.is_set(): progress_cb(len(results), total, res)
                refill()
        except KeyboardInterrupt: stop_event.set()
        finally:
            for fut in active: fut.cancel()
            ex.shutdown(wait=not stop_event.is_set(), cancel_futures=True)
            for fut in active:
                if fut.done() and not fut.cancelled() and (r := fut.result()): results.append(r)
        results.sort(key=lambda r: r.port)
        return ScanResultSet(results, len(results), total, stop_event.is_set())

    def scan(self, ports: list[int], mode: str = "fast", detect_services: bool = True, progress_cb: Optional[Callable] = None, stop_event: Optional[threading.Event] = None) -> ScanResultSet:
        """Scan a list of ports using 'fast' (threaded) or 'sequential' mode."""
        if mode in ("fast", "threaded"): return self.scan_threaded(ports, detect_services, progress_cb, stop_event)
        if mode == "sequential": return self.scan_sequential(ports, detect_services, progress_cb, stop_event)
        raise ValueError(f"Unknown mode: {mode}")


# ============================================================================
# CLI Helpers & Report Formatting
# ============================================================================

def ask_choice(prompt: str, choices: list[str], default: Optional[str] = None) -> str:
    while True:
        val = input(prompt).strip()
        if not val and default is not None: return default
        if val in choices: return val
        print(f"  Invalid choice. Options: {', '.join(choices)}")


def ask_number(prompt: str, min_val: int, max_val: int) -> int:
    while True:
        try:
            val = int(input(prompt).strip())
            if min_val <= val <= max_val: return val
        except ValueError: pass
        print(f"  Enter a number between {min_val} and {max_val}.")


def clear_line() -> None:
    """Clear terminal line cleanly without cursor manipulation artifacts."""
    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()


def live_progress(completed: int, total: int, result: ScanResult) -> None:
    """Display real-time scan progress and announce open ports immediately."""
    if result.state == "OPEN":
        clear_line()
        lat = f"{result.latency:.1f}ms" if result.latency is not None else ""
        banner_str = f" | {result.banner}" if result.banner else ""
        print(f"  [+] OPEN: Port {result.port:<5} | {result.service:<10} | {lat}{banner_str}")
    if total > 0:
        pct = (completed / total) * 100
        sys.stdout.write(f"\r  Scanning: {completed}/{total} ({pct:.1f}%)")
        sys.stdout.flush()


def ask_target() -> str:
    """Prompt for a target IP address or hostname and validate resolution."""
    while True:
        if not (t := input("\nEnter target IP address or hostname:\n> ").strip()):
            print("  Target cannot be empty.")
            continue
        clean_target = normalize_target(t)
        try:
            ip = socket.gethostbyname(clean_target)
            print(f"  Target resolved to: {ip}")
            return clean_target
        except socket.gaierror as e:
            print(f"  Could not resolve '{clean_target}': {e}. Please try again.")


def ask_custom_ports() -> list[int]:
    """Prompt user for a comma-separated list of ports and ranges."""
    while True:
        try:
            ports = []
            for item in input("  Enter ports (e.g. 22,80,443,5000-5010):\n  > ").split(","):
                if not item.strip(): continue
                s, *e = map(int, item.split("-", 1))
                rng = range(s, (e[0] if e else s) + 1)
                if not (1 <= rng.start <= 65535 and 1 <= rng.stop - 1 <= 65535 and rng.start <= rng.stop - 1): raise ValueError
                ports.extend(rng)
            if ports: return sorted(set(ports))
            print("  No valid ports entered.")
        except ValueError: print("  Invalid port entry. Ports must be 1-65535.")


def ask_mode() -> str:
    """Prompt user for scanning execution mode."""
    print("\nScan mode:\n  [1] Fast (Threaded)\n  [2] Sequential")
    return "fast" if ask_choice("\nSelect [1/2, default: 1]: ", ["1", "2"], default="1") == "1" else "sequential"


def ask_service_detection() -> bool:
    """Prompt user to toggle service & banner detection."""
    print("\nService/Banner detection:\n  [1] Enabled\n  [2] Disabled")
    return ask_choice("\nSelect [1/2, default: 1]: ", ["1", "2"], default="1") == "1"


def print_report(target: str, ip: str, mode: str, duration: float, res: ScanResultSet) -> None:
    """Render cleanly formatted final port scan report with honest TCP classifications."""
    c_open = sum(1 for r in res.results if r.state == "OPEN")
    c_closed = sum(1 for r in res.results if r.state == "CLOSED")
    c_no_resp = sum(1 for r in res.results if r.state == "NO RESPONSE")
    c_error = sum(1 for r in res.results if r.state == "ERROR")

    print(f"\n[FINAL SCAN REPORT]\n  Target        : {target} ({ip})\n  Scan Mode     : {mode.upper()}\n  Duration      : {duration:.2f}s\n  Total Scanned : {len(res.results)}")
    print(f"\n  Open          : {c_open}\n  Closed        : {c_closed}\n  No Response   : {c_no_resp}")
    if c_error > 0:
        print(f"  Errors        : {c_error}")

    print(f"\n[SCAN SUMMARY]\n  {c_open} ports accepted TCP connections.\n  {c_closed} ports explicitly rejected the connection.\n  {c_no_resp} ports did not respond before the timeout.")
    if c_error > 0:
        print(f"  {c_error} ports encountered network/socket errors.")
    print("\n  Note: \"No Response\" does not mean the ports are closed.\n  The host or an intermediate firewall may be filtering or dropping probes.")

    print("\n[DISCOVERED OPEN PORTS]")
    if not res.open_ports:
        print("  No open ports detected.")
        return
    print(f"  {'PORT':<8} {'STATE':<8} {'SERVICE':<12} {'LATENCY':<10} {'BANNER'}\n  " + "-" * 70)
    for r in res.open_ports:
        lat = f"{r.latency:.1f}ms" if r.latency is not None else "N/A"
        print(f"  {r.port:<8} {r.state:<8} {r.service:<12} {lat:<10} {r.banner or 'N/A'}")


# ============================================================================
# Interactive CLI Workflow
# ============================================================================

def interactive_scan() -> None:
    """Main interactive menu and scanning loop."""
    print("=" * 50 + f"\nNETRA v{__version__} — Network Reconnaissance Toolkit\n" + "=" * 50)
    while True:
        try:
            print("\nSelect action:\n  [1] Quick Scan (Common Services)\n  [2] Custom Port Range\n  [3] Custom Port List\n  [4] Exit")
            action = ask_choice("\nSelect [1-4, default: 1]: ", ["1", "2", "3", "4"], default="1")
            if action == "4": return print("\n  Goodbye!\n")

            target = ask_target()
            ip = socket.gethostbyname(target)
            if action == "1": ports = list(QUICK_PORTS)
            elif action == "2":
                start = ask_number("  Start port (1-65535): ", 1, 65535)
                ports = list(range(start, ask_number(f"  End port ({start}-65535): ", start, 65535) + 1))
            else: ports = ask_custom_ports()

            mode, detect = ask_mode(), ask_service_detection()
            print(f"\n[SCAN CONFIGURATION]\n  Target                  : {target} ({ip})\n  No of Ports to scan     : {len(ports)}\n  Mode                    : {mode.upper()}\n  Service detection       : {'Enabled' if detect else 'Disabled'}\n\n[SCAN IN PROGRESS]")
            start = time.perf_counter()
            res = PortScanner(target).scan(ports, mode=mode, detect_services=detect, progress_cb=live_progress)
            duration = time.perf_counter() - start

            # Smooth result transition: clear progress indicator and show summary
            clear_line()

            if res.interrupted:
                print(f"  [!] Scan interrupted by user.")
                print(f"  Completed {res.completed}/{res.total} ports in {duration:.2f}s.\n")
                if ask_choice("  [1] Return to main menu\n  [2] Exit scanner\n  Select [1/2, default: 1]: ", ["1", "2"], default="1") == "1":
                    continue
                return print("\n  Goodbye!\n")

            print(f"  Scan complete: {res.completed}/{res.total} ports scanned in {duration:.2f}s.")
            print_report(target, ip, mode, duration, res)

            if ask_choice("\nPerform another scan? [y/N]: ", ["y", "n", "yes", "no"], default="n") not in ("y", "yes"):
                return print("\n  Goodbye!\n")
        except KeyboardInterrupt:
            return print("\n\n  Scanner terminated by user.\n")


if __name__ == "__main__":
    try: interactive_scan()
    except KeyboardInterrupt: print("\n\n  Scanner terminated by user.\n"); sys.exit(0)