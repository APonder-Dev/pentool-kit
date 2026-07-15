"""Recon / OSINT: DNS records, reverse DNS, and passive subdomain enumeration.

Subdomain discovery uses a built-in wordlist resolved via DNS (active) plus
optional certificate-transparency lookup via crt.sh (passive) when --ct is set
and network access to crt.sh is available.
"""

from __future__ import annotations

import json
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..common import Finding, Report, Timer, good, info, warn

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

SUBDOMAIN_WORDS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
    "secure", "vpn", "admin", "portal", "dev", "staging", "test", "api", "app",
    "cdn", "cloud", "git", "gitlab", "jenkins", "jira", "shop", "store", "m",
    "mobile", "beta", "demo", "docs", "support", "help", "status", "dashboard",
    "auth", "sso", "login", "db", "sql", "mysql", "backup", "old", "new",
    "internal", "intranet", "proxy", "gateway", "router", "firewall", "monitor",
]


def _resolve(name: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(name, None)
        return sorted({i[4][0] for i in infos})
    except socket.gaierror:
        return []


def _dns_records(domain: str, report: Report) -> None:
    """Resolve basic records. Uses dnspython if available, else socket A/AAAA."""
    try:
        import dns.resolver  # type: ignore

        resolver = dns.resolver.Resolver()
        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype, lifetime=5)
                for r in answers:
                    val = r.to_text()
                    good(f"{domain} {rtype} {val}")
                    report.add(Finding(domain, "dns", f"{rtype} {val}", "info",
                                       data={"type": rtype, "value": val}))
            except Exception:
                continue
    except ImportError:
        warn("dnspython not installed - falling back to A/AAAA lookup only "
             "(pip install dnspython for full records)")
        ips = _resolve(domain)
        for ip in ips:
            good(f"{domain} A/AAAA {ip}")
            report.add(Finding(domain, "dns", f"address {ip}", "info",
                               data={"value": ip}))


def _reverse_dns(domain: str, report: Report) -> None:
    for ip in _resolve(domain):
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            good(f"{ip} PTR {host}")
            report.add(Finding(domain, "dns", f"PTR {ip} -> {host}", "info"))
        except socket.herror:
            pass


def _brute_subdomains(domain: str, report: Report, workers: int) -> None:
    info(f"Resolving {len(SUBDOMAIN_WORDS)} candidate subdomains")

    def check(word: str):
        fqdn = f"{word}.{domain}"
        ips = _resolve(fqdn)
        return (fqdn, ips) if ips else None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(check, w) for w in SUBDOMAIN_WORDS]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                fqdn, ips = res
                good(f"subdomain {fqdn} -> {', '.join(ips)}")
                report.add(Finding(domain, "dns", f"subdomain {fqdn}", "info",
                                   detail=", ".join(ips),
                                   data={"fqdn": fqdn, "ips": ips}))


def _crt_sh(domain: str, report: Report) -> None:
    """Passive subdomain enumeration via certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    info("Querying crt.sh certificate transparency logs")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "pentool/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:
        warn(f"crt.sh query failed ({e})")
        return
    names: set[str] = set()
    for entry in data:
        for n in entry.get("name_value", "").split("\n"):
            n = n.strip().lstrip("*.").lower()
            if n.endswith(domain):
                names.add(n)
    for n in sorted(names):
        good(f"ct-log {n}")
        report.add(Finding(domain, "dns", f"CT-log name {n}", "info",
                           data={"source": "crt.sh"}))


def run(args) -> Report:
    report = Report(tool="recon", target_spec=args.domain)
    domain = args.domain.strip().lower()
    info(f"Reconnaissance on {domain}")
    with Timer() as t:
        _dns_records(domain, report)
        _reverse_dns(domain, report)
        if not args.no_brute:
            _brute_subdomains(domain, report, args.workers)
        if args.ct:
            _crt_sh(domain, report)
    info(f"Done in {t.elapsed:.1f}s")
    return report
