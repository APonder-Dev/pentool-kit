"""Network scanner: TCP connect port scan with lightweight banner grabbing.

Uses only the standard library so it runs unmodified on Kali and Windows.
A TCP connect scan is chosen over raw SYN scanning so it needs no root/admin
privileges and no external packet library.
"""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..common import Finding, Report, Timer, expand_targets, good, info, parse_ports, resolve_host

# Common service names for well-known ports (fallback when getservbyport fails).
SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "microsoft-ds", 587: "smtp-submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 5985: "winrm", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb", 11211: "memcached",
}

TLS_PORTS = {443, 465, 993, 995, 8443}


def _service_name(port: int) -> str:
    if port in SERVICE_HINTS:
        return SERVICE_HINTS[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def _grab_banner(host: str, port: int, timeout: float) -> str:
    """Best-effort banner grab; returns a short printable string or ''."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in TLS_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    ver = tls.version()
                    return f"TLS {ver}" + (f" cn={_cert_cn(cert)}" if cert else "")
            # For plain HTTP-ish ports, nudge the server to respond.
            if port in (80, 8080, 8000, 8008, 8888, 3000):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(256)
            return data.decode("latin-1", "replace").strip().split("\r\n")[0][:120]
    except Exception:
        return ""


def _cert_cn(cert) -> str:
    for tup in cert.get("subject", ()):  # type: ignore[union-attr]
        for k, v in tup:
            if k == "commonName":
                return v
    return "?"


# Small payloads that coax a reply from common UDP services.
UDP_PAYLOADS = {
    53: bytes.fromhex("0000010000010000000000000377777706676f6f676c6503636f6d0000010001"),
    123: b"\x1b" + 47 * b"\0",                      # NTP client request
    161: bytes.fromhex("302902010004067075626c6963a01c02040000000002010002"
                       "0100300e300c06082b060102010105000500"),  # SNMP get
    137: bytes.fromhex("a2480010000100000000000020434b41414141"
                       "41414141414141414141414141414141414100002100010000"),  # NetBIOS
}

# Ports probed to decide whether a host is alive during discovery.
DISCOVERY_PORTS = [443, 80, 22, 445, 3389, 53]


def _is_alive(host: str, timeout: float) -> bool:
    """TCP ping sweep: a host is 'alive' if any probe port either accepts the
    connection or actively refuses it (both prove the host answered)."""
    for port in DISCOVERY_PORTS:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return True
        except (socket.timeout, TimeoutError):
            continue
        except OSError:
            continue
    return False


def _scan_udp_one(host: str, port: int, timeout: float) -> tuple[int, str] | None:
    """Connected-UDP probe. Returns (port, state) for open / open|filtered;
    None when the port is definitively closed (ICMP port-unreachable)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.send(UDP_PAYLOADS.get(port, b"\x00"))
        try:
            sock.recv(1024)
            return port, "open"
        except (socket.timeout, TimeoutError):
            return port, "open|filtered"
        except (ConnectionRefusedError, ConnectionResetError):
            return None
    except OSError:
        return None
    finally:
        sock.close()


def scan_udp_host(host: str, ports: list[int], timeout: float, workers: int,
                  report: Report) -> int:
    ip = resolve_host(host) or host
    found = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scan_udp_one, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res is None:
                continue
            port, state = res
            found += 1
            svc = _service_name(port)
            sev = "info" if state == "open" else "info"
            good(f"{host} ({ip}) {port}/udp {state}  {svc}")
            report.add(Finding(
                target=host, category="port",
                title=f"{port}/udp {state} ({svc})", severity=sev,
                data={"ip": ip, "port": port, "proto": "udp",
                      "service": svc, "state": state},
            ))
    return found


def _scan_one(host: str, port: int, timeout: float, banners: bool) -> tuple[int, str] | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except (OSError, socket.timeout):
        return None
    banner = _grab_banner(host, port, timeout) if banners else ""
    return port, banner


def scan_host(host: str, ports: list[int], timeout: float, workers: int, banners: bool,
              report: Report) -> int:
    ip = resolve_host(host) or host
    open_count = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scan_one, host, p, timeout, banners): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res is None:
                continue
            port, banner = res
            open_count += 1
            svc = _service_name(port)
            detail = f"{svc}" + (f" | {banner}" if banner else "")
            good(f"{host} ({ip}) {port}/tcp open  {detail}")
            report.add(Finding(
                target=host, category="port",
                title=f"{port}/tcp open ({svc})",
                severity="info", detail=banner,
                data={"ip": ip, "port": port, "service": svc, "banner": banner},
            ))
    return open_count


def discover_hosts(targets: list[str], timeout: float, workers: int,
                   report: Report) -> list[str]:
    """Return the subset of targets that respond to a TCP ping sweep."""
    info(f"Host discovery across {len(targets)} target(s)")
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_is_alive, h, timeout): h for h in targets}
        for fut in as_completed(futures):
            host = futures[fut]
            if fut.result():
                alive.append(host)
                good(f"host up: {host}")
                report.add(Finding(host, "host", "host is up", "info",
                                   data={"ip": resolve_host(host) or host}))
    info(f"{len(alive)}/{len(targets)} host(s) up")
    return alive


def run(args) -> Report:
    proto = "udp" if getattr(args, "udp", False) else "tcp"
    report = Report(tool=f"network-scan-{proto}", target_spec=args.target)
    targets = expand_targets(args.target)
    ports = parse_ports(args.ports)

    total = 0
    with Timer() as t:
        if getattr(args, "discover", False):
            targets = discover_hosts(targets, args.timeout, args.workers, report)
            if not targets:
                info("No live hosts; nothing to scan.")
                return report

        info(f"Scanning {len(targets)} host(s) x {len(ports)} {proto} port(s), "
             f"{args.workers} workers, {args.timeout}s timeout")
        for host in targets:
            if proto == "udp":
                total += scan_udp_host(host, ports, args.timeout, args.workers, report)
            else:
                total += scan_host(host, ports, args.timeout, args.workers,
                                   not args.no_banner, report)
    info(f"Done in {t.elapsed:.1f}s - {total} open {proto} port(s) "
         f"across {len(targets)} host(s)")
    return report
