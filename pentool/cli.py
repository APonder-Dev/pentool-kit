"""Command-line interface for pentool.

Subcommands:
  scan   TCP port scan + banner grab
  web    web app security header / TLS / exposed path audit
  recon  DNS + subdomain reconnaissance
  vuln   service fingerprint + risky-exposure + optional CVE lookup
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .common import BANNER, err, require_authorization
from .scanners import network, recon, tls_audit, vuln, web


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pentool",
        description="Authorized penetration-testing & self-audit toolkit.",
        epilog="Use only on systems you own or are explicitly authorized to test.",
    )
    p.add_argument("--version", action="version", version=f"pentool {__version__}")

    # Global flags usable before OR after the subcommand.
    # default=SUPPRESS so a subcommand without the flag does NOT clobber a value
    # already set by the top-level parser (i.e. flags placed before the subcommand).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-y", "--yes", action="store_true", default=argparse.SUPPRESS,
                        help="skip the interactive authorization prompt (lab/CI use)")
    common.add_argument("-o", "--output", metavar="FILE", default=argparse.SUPPRESS,
                        help="write full findings to a report file")
    common.add_argument("-f", "--format", choices=["json", "html", "md", "csv"],
                        default=argparse.SUPPRESS,
                        help="report format (default: inferred from -o extension, else json)")
    p.add_argument("-y", "--yes", action="store_true", default=False, help=argparse.SUPPRESS)
    p.add_argument("-o", "--output", metavar="FILE", default=None, help=argparse.SUPPRESS)
    p.add_argument("-f", "--format", choices=["json", "html", "md", "csv"],
                   default=None, help=argparse.SUPPRESS)

    sub = p.add_subparsers(dest="command", required=True, parser_class=argparse.ArgumentParser)

    # scan ------------------------------------------------------------------
    s = sub.add_parser("scan", parents=[common], help="TCP port scan with banner grabbing")
    s.add_argument("target", help="host, IP, CIDR, or comma-separated list")
    s.add_argument("-p", "--ports", default="top",
                   help="ports: 'top', '1-1024', or '22,80,443' (default: top)")
    s.add_argument("-w", "--workers", type=int, default=200, help="concurrent sockets")
    s.add_argument("-t", "--timeout", type=float, default=1.0, help="per-port timeout (s)")
    s.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    s.add_argument("--udp", action="store_true",
                   help="scan UDP instead of TCP (open|filtered results)")
    s.add_argument("--discover", action="store_true",
                   help="TCP ping-sweep first; only scan hosts that are up")
    s.set_defaults(func=network.run)

    # web -------------------------------------------------------------------
    w = sub.add_parser("web", parents=[common], help="web app TLS/header/exposed-path audit")
    w.add_argument("url", help="target URL or host (e.g. https://example.com)")
    w.add_argument("-t", "--timeout", type=float, default=8.0, help="request timeout (s)")
    w.add_argument("--no-paths", action="store_true", help="skip sensitive-path probing")
    w.set_defaults(func=web.run)

    # recon -----------------------------------------------------------------
    r = sub.add_parser("recon", parents=[common], help="DNS + subdomain reconnaissance")
    r.add_argument("domain", help="target domain (e.g. example.com)")
    r.add_argument("-w", "--workers", type=int, default=50, help="concurrent resolvers")
    r.add_argument("--no-brute", action="store_true", help="skip subdomain brute force")
    r.add_argument("--ct", action="store_true",
                   help="also query crt.sh certificate transparency logs")
    r.set_defaults(func=recon.run)

    # vuln ------------------------------------------------------------------
    v = sub.add_parser("vuln", parents=[common], help="fingerprint services + flag risky exposures")
    v.add_argument("target", help="host, IP, CIDR, or comma-separated list")
    v.add_argument("-p", "--ports", default="top", help="ports to check (default: top)")
    v.add_argument("-w", "--workers", type=int, default=200, help="concurrent sockets")
    v.add_argument("-t", "--timeout", type=float, default=1.5, help="per-port timeout (s)")
    v.add_argument("--cve", action="store_true",
                   help="query NVD for CVEs matching identified product versions")
    v.set_defaults(func=vuln.run)

    # tls -------------------------------------------------------------------
    tl = sub.add_parser("tls", parents=[common],
                        help="deep TLS/SSL audit: protocols, cert validity, expiry")
    tl.add_argument("target", help="host, host:port, or https URL (default port 443)")
    tl.add_argument("-t", "--timeout", type=float, default=6.0, help="handshake timeout (s)")
    tl.set_defaults(func=tls_audit.run)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    require_authorization(assume_yes=args.yes)

    try:
        report = args.func(args)
    except KeyboardInterrupt:
        err("Interrupted by user.")
        return 130
    except Exception as e:  # keep CLI robust; surface the error cleanly
        err(f"Error: {e}")
        return 1

    report.print_summary()
    if args.output:
        report.save(args.output, fmt=args.format)
    return 0


if __name__ == "__main__":
    sys.exit(main())
