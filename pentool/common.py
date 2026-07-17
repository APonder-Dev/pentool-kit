"""Shared helpers: authorization gate, logging, output formatting, timing."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Iterable


# --- terminal colors (auto-disabled when not a TTY or on NO_COLOR) -----------

class C:
    _on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RESET = "\033[0m" if _on else ""
    BOLD = "\033[1m" if _on else ""
    DIM = "\033[2m" if _on else ""
    RED = "\033[31m" if _on else ""
    GREEN = "\033[32m" if _on else ""
    YELLOW = "\033[33m" if _on else ""
    BLUE = "\033[34m" if _on else ""
    CYAN = "\033[36m" if _on else ""


def info(msg: str) -> None:
    print(f"{C.CYAN}[*]{C.RESET} {msg}")


def good(msg: str) -> None:
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def err(msg: str) -> None:
    print(f"{C.RED}[-]{C.RESET} {msg}", file=sys.stderr)


# --- authorization gate ------------------------------------------------------

CONSENT_ENV = "PENTOOL_AUTHORIZED"

BANNER = f"""{C.BOLD}pentool{C.RESET} - authorized security testing toolkit
{C.DIM}Use only against assets you own or are explicitly authorized to test.{C.RESET}
"""


def require_authorization(assume_yes: bool = False) -> None:
    """Block execution until the operator confirms they are authorized.

    Set the env var PENTOOL_AUTHORIZED=1 (or pass --yes) in automated/lab runs.
    """
    if assume_yes or os.environ.get(CONSENT_ENV) == "1":
        return
    print(BANNER)
    try:
        answer = input(
            "Confirm you have written authorization to test the target(s) [y/N]: "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer not in ("y", "yes"):
        err("Authorization not confirmed. Aborting.")
        sys.exit(2)


# --- target parsing ----------------------------------------------------------

def resolve_host(host: str) -> str | None:
    """Resolve a hostname to an IP; returns None on failure."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def expand_targets(spec: str) -> list[str]:
    """Expand a target spec into individual host strings.

    Accepts a single host/IP, a CIDR range (192.168.1.0/24), or a
    comma-separated list of any of those.
    """
    out: list[str] = []
    for part in (p.strip() for p in spec.split(",") if p.strip()):
        try:
            net = ipaddress.ip_network(part, strict=False)
            if net.num_addresses > 1:
                out.extend(str(ip) for ip in net.hosts())
            else:
                out.append(str(net.network_address))
        except ValueError:
            out.append(part)  # hostname
    return out


def parse_ports(spec: str) -> list[int]:
    """Parse a port spec like '22,80,443' or '1-1024' or 'top' into a list."""
    if spec == "top":
        return sorted(TOP_PORTS)
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


# A compact "top ports" set for quick scans.
TOP_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432,
    5900, 5985, 6379, 8000, 8008, 8080, 8443, 8888, 9200, 9300, 11211, 27017,
}


# --- report model ------------------------------------------------------------

@dataclass
class Finding:
    target: str
    category: str          # e.g. "port", "web", "dns", "vuln"
    title: str
    severity: str = "info"  # info | low | medium | high | critical
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Report:
    tool: str
    target_spec: str
    started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    # -- serialization formats ------------------------------------------

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def _sorted_findings(self) -> list[Finding]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(self.findings, key=lambda x: order.get(x.severity, 9))

    def to_csv(self) -> str:
        import csv
        import io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["severity", "category", "target", "title", "detail"])
        for f in self._sorted_findings():
            w.writerow([f.severity, f.category, f.target, f.title, f.detail])
        return buf.getvalue()

    def to_markdown(self) -> str:
        lines = [
            f"# {self.tool} report",
            "",
            f"- **Target:** `{self.target_spec}`",
            f"- **Started:** {self.started}",
            f"- **Findings:** {len(self.findings)}",
            "",
            "| Severity | Category | Target | Finding | Detail |",
            "| --- | --- | --- | --- | --- |",
        ]
        for f in self._sorted_findings():
            detail = (f.detail or "").replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {f.severity.upper()} | {f.category} | {f.target} "
                f"| {f.title.replace('|', chr(92) + '|')} | {detail} |"
            )
        if not self.findings:
            lines.append("| INFO | - | - | No findings | - |")
        return "\n".join(lines) + "\n"

    def to_html(self) -> str:
        import html as _html
        colors = {
            "critical": "#7c1d1d", "high": "#b91c1c", "medium": "#b45309",
            "low": "#1d4ed8", "info": "#4b5563",
        }
        rows = []
        for f in self._sorted_findings():
            c = colors.get(f.severity, "#4b5563")
            rows.append(
                f'<tr><td><span class="sev" style="background:{c}">'
                f"{_html.escape(f.severity.upper())}</span></td>"
                f"<td>{_html.escape(f.category)}</td>"
                f"<td>{_html.escape(f.target)}</td>"
                f"<td>{_html.escape(f.title)}</td>"
                f"<td>{_html.escape(f.detail or '')}</td></tr>"
            )
        if not rows:
            rows.append('<tr><td colspan="5">No findings.</td></tr>')
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{_html.escape(self.tool)} report - {_html.escape(self.target_spec)}</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #111; }}
 h1 {{ margin-bottom: .2rem; }}
 .meta {{ color: #555; margin-bottom: 1.5rem; }}
 table {{ border-collapse: collapse; width: 100%; }}
 th, td {{ text-align: left; padding: .5rem .7rem; border-bottom: 1px solid #eee; }}
 th {{ background: #f7f7f8; }}
 .sev {{ color: #fff; padding: .1rem .5rem; border-radius: .3rem; font-size: .8rem; }}
</style></head><body>
<h1>{_html.escape(self.tool)} report</h1>
<div class="meta">Target: <code>{_html.escape(self.target_spec)}</code> &middot;
 Started: {_html.escape(self.started)} &middot; {len(self.findings)} finding(s)</div>
<table><thead><tr><th>Severity</th><th>Category</th><th>Target</th>
<th>Finding</th><th>Detail</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</body></html>
"""

    def save(self, path: str, fmt: str | None = None) -> None:
        """Write the report. Format is taken from `fmt`, else the file
        extension, else JSON."""
        if fmt is None:
            ext = os.path.splitext(path)[1].lower().lstrip(".")
            fmt = {"json": "json", "html": "html", "htm": "html",
                   "md": "md", "markdown": "md", "csv": "csv"}.get(ext, "json")
        renderer = {
            "json": self.to_json, "html": self.to_html,
            "md": self.to_markdown, "csv": self.to_csv,
        }.get(fmt, self.to_json)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(renderer())
        good(f"Report written to {path} ({fmt})")

    def print_summary(self) -> None:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        color = {
            "critical": C.RED + C.BOLD, "high": C.RED, "medium": C.YELLOW,
            "low": C.BLUE, "info": C.DIM,
        }
        if not self.findings:
            warn("No findings.")
            return
        print(f"\n{C.BOLD}=== {self.tool} results for {self.target_spec} ==={C.RESET}")
        for f in sorted(self.findings, key=lambda x: order.get(x.severity, 9)):
            tag = f"{color.get(f.severity, '')}{f.severity.upper():>8}{C.RESET}"
            line = f"  {tag}  {f.target}  {f.title}"
            print(line)
            if f.detail:
                print(f"           {C.DIM}{f.detail}{C.RESET}")


class Timer:
    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.elapsed = time.perf_counter() - self.t0
