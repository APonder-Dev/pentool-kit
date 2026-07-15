"""Web application checks: TLS, security headers, cookie flags, exposed paths.

Non-intrusive by design. It performs simple GET/HEAD requests only and does not
attempt exploitation. Intended for auditing your own web assets or scoped targets.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..common import Finding, Report, Timer, good, info, warn

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS missing", "medium"),
    "content-security-policy": ("Content-Security-Policy missing", "medium"),
    "x-frame-options": ("X-Frame-Options missing (clickjacking)", "low"),
    "x-content-type-options": ("X-Content-Type-Options missing (MIME sniffing)", "low"),
    "referrer-policy": ("Referrer-Policy missing", "info"),
    "permissions-policy": ("Permissions-Policy missing", "info"),
}

# Common sensitive paths worth checking for accidental exposure.
COMMON_PATHS = [
    "/.git/config", "/.env", "/.env.local", "/config.php", "/wp-config.php",
    "/phpinfo.php", "/server-status", "/.svn/entries", "/backup.zip",
    "/robots.txt", "/.well-known/security.txt", "/admin", "/actuator/health",
    "/api", "/swagger-ui.html", "/.DS_Store",
]


def _split_url(url: str) -> tuple[str, str, int, str]:
    if "://" not in url:
        url = "http://" + url
    p = urllib.parse.urlparse(url)
    scheme = p.scheme or "http"
    host = p.hostname or ""
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    return scheme, host, port, path


def _request(scheme: str, host: str, port: int, path: str, timeout: float,
             method: str = "GET"):
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path, headers={"User-Agent": "pentool/1.0 (audit)"})
        resp = conn.getresponse()
        body = resp.read(2048)
        return resp.status, dict(resp.getheaders()), body
    finally:
        conn.close()


def _check_tls(host: str, port: int, timeout: float, report: Report) -> None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                ver = tls.version()
                if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                    report.add(Finding(host, "web", f"Weak TLS version {ver}",
                                       "high", "Server negotiated an outdated protocol."))
                    warn(f"{host}: weak TLS {ver}")
                else:
                    good(f"{host}: TLS {ver}")
    except Exception as e:
        warn(f"{host}: TLS check failed ({e})")


def _check_headers(scheme, host, port, path, timeout, report: Report) -> None:
    try:
        status, headers, _ = _request(scheme, host, port, path, timeout)
    except Exception as e:
        warn(f"{host}: request failed ({e})")
        return
    good(f"{host} {scheme}://{host}:{port}{path} -> HTTP {status}")
    lower = {k.lower(): v for k, v in headers.items()}

    server = lower.get("server")
    if server:
        report.add(Finding(host, "web", f"Server header discloses: {server}",
                           "info", data={"server": server}))

    for hdr, (title, sev) in SECURITY_HEADERS.items():
        if hdr not in lower:
            report.add(Finding(host, "web", title, sev))

    cookie = lower.get("set-cookie", "")
    if cookie:
        flags = cookie.lower()
        if "httponly" not in flags:
            report.add(Finding(host, "web", "Cookie missing HttpOnly flag", "low"))
        if scheme == "https" and "secure" not in flags:
            report.add(Finding(host, "web", "Cookie missing Secure flag", "low"))


def _check_paths(scheme, host, port, timeout, report: Report) -> None:
    def probe(path: str):
        try:
            status, _, body = _request(scheme, host, port, path, timeout)
            return path, status, len(body)
        except Exception:
            return path, None, 0

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(probe, p) for p in COMMON_PATHS]
        for fut in as_completed(futures):
            path, status, size = fut.result()
            if status and status < 400:
                sev = "high" if path in ("/.git/config", "/.env", "/.env.local",
                                         "/wp-config.php") else "medium"
                if path in ("/robots.txt", "/.well-known/security.txt"):
                    sev = "info"
                report.add(Finding(host, "web", f"Exposed path {path} (HTTP {status})",
                                   sev, data={"path": path, "status": status}))
                warn(f"{host}: {path} -> HTTP {status} ({size}b)")


def run(args) -> Report:
    report = Report(tool="web-scan", target_spec=args.url)
    scheme, host, port, path = _split_url(args.url)
    info(f"Auditing {scheme}://{host}:{port}{path}")
    with Timer() as t:
        if scheme == "https":
            _check_tls(host, port, args.timeout, report)
        _check_headers(scheme, host, port, path, args.timeout, report)
        if not args.no_paths:
            _check_paths(scheme, host, port, args.timeout, report)
    info(f"Done in {t.elapsed:.1f}s")
    return report
