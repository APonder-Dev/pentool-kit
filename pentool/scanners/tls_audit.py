"""TLS/SSL deep audit: protocol support, certificate validity, expiry, SANs.

Uses only the standard library. Protocol support is probed by attempting a
handshake pinned to each version; certificate details are read from a verified
handshake when possible, with an unverified fallback so self-signed/expired
certs can still be inspected.
"""

from __future__ import annotations

import socket
import ssl
import tempfile
from datetime import datetime, timezone

from ..common import Finding, Report, Timer, good, info, warn

# (label, ssl.TLSVersion, severity-if-supported)
PROTO_VERSIONS = [
    ("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None), "high"),
    ("TLSv1.0", ssl.TLSVersion.TLSv1, "high"),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "medium"),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, "info"),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, "info"),
]


def _split(target: str) -> tuple[str, int]:
    if target.startswith("https://"):
        target = target[len("https://"):]
    target = target.rstrip("/")
    if ":" in target:
        host, port = target.rsplit(":", 1)
        return host, int(port)
    return target, 443


def _probe_version(host: str, port: int, version, timeout: float) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return False  # this build cannot pin that version
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _check_protocols(host: str, port: int, timeout: float, report: Report) -> None:
    supported = []
    for label, version, sev in PROTO_VERSIONS:
        if version is None:
            continue
        if _probe_version(host, port, version, timeout):
            supported.append(label)
            if sev in ("high", "medium"):
                report.add(Finding(host, "tls", f"Weak protocol supported: {label}",
                                   sev, "Disable this legacy protocol version."))
                warn(f"{host}: supports {label}")
            else:
                good(f"{host}: supports {label}")
    if supported and "TLSv1.2" not in supported and "TLSv1.3" not in supported:
        report.add(Finding(host, "tls", "No modern TLS (1.2/1.3) offered", "high"))
    if not supported:
        report.add(Finding(host, "tls", "No TLS handshake succeeded", "medium",
                           "Host may not speak TLS on this port."))


def _decode_cert_pem(pem: str) -> dict:
    """Decode a PEM certificate to the ssl dict form, even if untrusted.

    Uses the stdlib helper ssl._ssl._test_decode_cert (stable for years); if it
    is ever unavailable we degrade gracefully to an empty dict.
    """
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:
        return {}


def _cert_field(cert: dict, key: str) -> str:
    for tup in cert.get(key, ()):  # subject / issuer are tuples of tuples
        for k, v in tup:
            if k in ("commonName", "organizationName"):
                return v
    return "?"


def _check_certificate(host: str, port: int, timeout: float, report: Report) -> None:
    # First, determine trust status via a verifying handshake.
    verify_ok = True
    verify_reason = ""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                good(f"{host}: certificate trusted (negotiated {tls.version()})")
    except ssl.SSLCertVerificationError as e:
        verify_ok = False
        verify_reason = getattr(e, "verify_message", "") or str(e)
    except Exception as e:
        warn(f"{host}: TLS connection failed ({e})")
        return

    if not verify_ok:
        sev = "high" if ("expired" in verify_reason or "self" in verify_reason.lower()) \
            else "medium"
        report.add(Finding(host, "tls", f"Certificate not trusted: {verify_reason}",
                           sev))
        warn(f"{host}: cert verification failed - {verify_reason}")

    # Fetch the cert regardless of trust to read subject/SAN/expiry.
    try:
        pem = ssl.get_server_certificate((host, port), timeout=timeout)
    except TypeError:
        pem = ssl.get_server_certificate((host, port))  # older signature
    except Exception as e:
        warn(f"{host}: could not retrieve certificate ({e})")
        return
    cert = _decode_cert_pem(pem)
    if not cert:
        return

    subject = _cert_field(cert, "subject")
    issuer = _cert_field(cert, "issuer")
    report.add(Finding(host, "tls", f"Subject CN={subject}, Issuer={issuer}", "info",
                       data={"subject": subject, "issuer": issuer}))
    good(f"{host}: subject={subject} issuer={issuer}")

    sans = [v for typ, v in cert.get("subjectAltName", ()) if typ == "DNS"]
    if sans:
        report.add(Finding(host, "tls", f"SANs: {', '.join(sans[:10])}", "info",
                           data={"san": sans}))

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
            days = (expires - datetime.now(timezone.utc)).days
            if days < 0:
                report.add(Finding(host, "tls", f"Certificate EXPIRED {-days} day(s) ago",
                                   "critical", data={"notAfter": not_after}))
                warn(f"{host}: cert expired {-days}d ago")
            elif days <= 14:
                report.add(Finding(host, "tls", f"Certificate expires in {days} day(s)",
                                   "high", data={"notAfter": not_after}))
                warn(f"{host}: cert expires in {days}d")
            elif days <= 30:
                report.add(Finding(host, "tls", f"Certificate expires in {days} day(s)",
                                   "medium", data={"notAfter": not_after}))
            else:
                report.add(Finding(host, "tls", f"Certificate valid for {days} more day(s)",
                                   "info", data={"notAfter": not_after}))
                good(f"{host}: cert valid {days} more days")
        except ValueError:
            report.add(Finding(host, "tls", f"Certificate notAfter={not_after}", "info"))


def run(args) -> Report:
    report = Report(tool="tls-audit", target_spec=args.target)
    host, port = _split(args.target)
    info(f"TLS audit on {host}:{port}")
    with Timer() as t:
        _check_protocols(host, port, args.timeout, report)
        _check_certificate(host, port, args.timeout, report)
    info(f"Done in {t.elapsed:.1f}s")
    return report
