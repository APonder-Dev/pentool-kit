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


def run(args) -> Report:
    report = Report(tool="network-scan", target_spec=args.target)
    targets = expand_targets(args.target)
    ports = parse_ports(args.ports)
    info(f"Scanning {len(targets)} host(s) x {len(ports)} port(s), "
         f"{args.workers} workers, {args.timeout}s timeout")
    total_open = 0
    with Timer() as t:
        for host in targets:
            total_open += scan_host(host, ports, args.timeout, args.workers,
                                    not args.no_banner, report)
    info(f"Done in {t.elapsed:.1f}s - {total_open} open port(s) across {len(targets)} host(s)")
    return report
