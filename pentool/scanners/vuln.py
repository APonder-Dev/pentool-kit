"""Vuln checker: fingerprint services from banners and flag known-risky exposures.

This performs heuristic, non-exploitative checks:
  * matches service banners against a small local signature set,
  * flags plaintext/legacy protocols and dangerously exposed services,
  * optionally queries the public NVD 2.0 API for CVEs matching a product string.

It reuses the network scanner to collect open ports + banners first.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request

from ..common import Finding, Report, Timer, good, info, parse_ports, warn
from . import network

# Ports that expose plaintext or high-risk services when reachable.
RISKY_PORTS = {
    21: ("FTP (cleartext credentials)", "medium"),
    23: ("Telnet (cleartext, deprecated)", "high"),
    69: ("TFTP (no auth)", "medium"),
    111: ("RPC portmapper exposed", "medium"),
    135: ("MSRPC exposed", "medium"),
    139: ("NetBIOS exposed", "medium"),
    445: ("SMB exposed to network", "high"),
    1433: ("MSSQL exposed", "medium"),
    2049: ("NFS exposed", "high"),
    2375: ("Docker API unauthenticated (RCE risk)", "critical"),
    3306: ("MySQL exposed", "medium"),
    3389: ("RDP exposed (brute-force/BlueKeep surface)", "high"),
    5432: ("PostgreSQL exposed", "medium"),
    5900: ("VNC exposed", "high"),
    6379: ("Redis often unauthenticated (RCE risk)", "critical"),
    9200: ("Elasticsearch often unauthenticated", "high"),
    11211: ("Memcached exposed (amplification/data leak)", "high"),
    27017: ("MongoDB often unauthenticated", "critical"),
}

# Banner substring -> (product hint, note, severity).
BANNER_SIGNATURES = [
    (re.compile(r"OpenSSH[_/ ]([\d.]+)", re.I), "OpenSSH", "info"),
    (re.compile(r"vsftpd ([\d.]+)", re.I), "vsftpd", "info"),
    (re.compile(r"ProFTPD ([\d.]+)", re.I), "ProFTPD", "info"),
    (re.compile(r"Apache/([\d.]+)", re.I), "Apache httpd", "info"),
    (re.compile(r"nginx/([\d.]+)", re.I), "nginx", "info"),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I), "Microsoft IIS", "info"),
    (re.compile(r"Exim ([\d.]+)", re.I), "Exim", "info"),
    (re.compile(r"Postfix", re.I), "Postfix", "info"),
]

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _fingerprint(report: Report) -> list[tuple[str, str]]:
    """Scan port findings for banners; return (target, product-version) pairs."""
    products: list[tuple[str, str]] = []
    for f in list(report.findings):
        if f.category != "port":
            continue
        port = f.data.get("port")
        banner = f.data.get("banner", "")

        if port in RISKY_PORTS:
            title, sev = RISKY_PORTS[port]
            report.add(Finding(f.target, "vuln", title, sev,
                               detail=f"port {port}", data={"port": port}))
            warn(f"{f.target}:{port} {title}")

        for rx, product, _sev in BANNER_SIGNATURES:
            m = rx.search(banner)
            if m:
                version = m.group(1) if m.groups() else ""
                label = f"{product} {version}".strip()
                report.add(Finding(f.target, "vuln", f"Identified {label}",
                                   "info", detail=f"port {port}",
                                   data={"product": product, "version": version}))
                good(f"{f.target}:{port} fingerprint -> {label}")
                if version:
                    products.append((f.target, f"{product} {version}"))
                break
    return products


def _nvd_lookup(product_version: str, report: Report, target: str, limit: int = 5) -> None:
    """Query NVD 2.0 keyword search for CVEs matching a product string."""
    params = urllib.parse.urlencode({
        "keywordSearch": product_version,
        "resultsPerPage": limit,
    })
    url = f"{NVD_API}?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "pentool/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:
        warn(f"NVD lookup failed for '{product_version}' ({e})")
        return
    for item in data.get("vulnerabilities", [])[:limit]:
        cve = item.get("cve", {})
        cid = cve.get("id", "?")
        metrics = cve.get("metrics", {})
        score, sev = _cvss(metrics)
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:160]
                break
        report.add(Finding(target, "vuln", f"{cid} ({score}) - {product_version}",
                           _map_sev(sev), detail=desc,
                           data={"cve": cid, "cvss": score, "severity": sev}))
        warn(f"{target}: {cid} {sev} {score} - {desc[:80]}")


def _cvss(metrics: dict) -> tuple[str, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            cvss = arr[0].get("cvssData", {})
            score = cvss.get("baseScore", "?")
            sev = arr[0].get("baseSeverity") or cvss.get("baseSeverity", "UNKNOWN")
            return str(score), str(sev)
    return "?", "UNKNOWN"


def _map_sev(nvd_sev: str) -> str:
    return {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low",
    }.get(nvd_sev.upper(), "info")


def run(args) -> Report:
    report = Report(tool="vuln-check", target_spec=args.target)
    info(f"Vuln check on {args.target}")
    with Timer() as t:
        # Reuse the network scanner (with banners) to gather service info.
        class _NArgs:
            target = args.target
            ports = args.ports
            workers = args.workers
            timeout = args.timeout
            no_banner = False
        net_report = network.run(_NArgs())
        report.findings.extend(net_report.findings)

        products = _fingerprint(report)
        if args.cve and products:
            info(f"Querying NVD for {len(products)} identified product(s) "
                 f"(rate-limited; may be slow)")
            seen = set()
            for target, pv in products:
                if pv in seen:
                    continue
                seen.add(pv)
                _nvd_lookup(pv, report, target)
        elif args.cve:
            warn("No versioned products identified for CVE lookup.")
    info(f"Done in {t.elapsed:.1f}s")
    return report
