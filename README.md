# pentool

A modular, cross-platform (**Kali Linux** and **Windows**) penetration-testing and
self-audit toolkit written in Python. The core runs on the **standard library
alone** — no dependencies required — so it works on a fresh Kali box or a locked-down
Windows host without extra setup.

> ⚠️ **Authorized use only.** Run these tools solely against systems you own or
> have **explicit written permission** to test. The toolkit prompts for
> authorization on every run (bypass with `--yes` or `PENTOOL_AUTHORIZED=1` in a lab).
> See [SECURITY.md](SECURITY.md) for the acceptable-use policy.

## Contents

- [Modules](#modules) · [Install](#install) · [Usage](#usage) · [Reports](#reports)
- [Design notes](#design-notes) · [Full reference → WIKI.md](WIKI.md)
- [Security & acceptable use → SECURITY.md](SECURITY.md) · [License → LICENSE](LICENSE)
- [Changelog → CHANGELOG.md](CHANGELOG.md)

## Modules

| Command | Purpose |
|---------|---------|
| `scan`  | TCP/UDP port scan + banner grabbing, optional host discovery (no root/admin needed) |
| `web`   | Web audit: TLS version, security headers, cookie flags, exposed sensitive paths |
| `recon` | DNS records, reverse DNS, subdomain brute force, optional crt.sh CT logs |
| `vuln`  | Service fingerprinting, risky-exposure flagging, optional NVD CVE lookup |
| `tls`   | Deep TLS/SSL audit: protocol support, certificate validity, expiry, SANs |

Reports export to **JSON, HTML, Markdown, or CSV** (`-f/--format`, or inferred from
the `-o` file extension).

## Install

No install required — just run it:

```bash
python pentool.py --help
```

Or install as a package (adds the `pentool` command and optional richer DNS):

```bash
pip install -e ".[dns]"
pentool --help
```

Once published, it is also available from PyPI and as a container image:

```bash
pip install pentool-kit                 # provides the `pentool` command
docker run --rm ghcr.io/aponder-dev/pentool-kit scan 127.0.0.1 -p top -y
```

See [RELEASING.md](RELEASING.md) for how releases, PyPI, and the container image
are produced.

**Requirements:** Python 3.9+. The optional `dnspython` package unlocks full DNS
record types (MX/NS/TXT/SOA/CNAME) in `recon`; without it, `recon` still resolves
A/AAAA records.

## Usage

```bash
# Port scan the top ports on a host, save a JSON report
python pentool.py scan 192.168.1.10 -o report.json

# Scan a whole subnet on specific ports, no banners (faster)
python pentool.py scan 10.0.0.0/24 -p 22,80,443,3389 --no-banner

# Ping-sweep a subnet first, then scan only live hosts; export an HTML report
python pentool.py scan 10.0.0.0/24 --discover -o report.html

# UDP scan common services
python pentool.py scan 192.168.1.10 -p 53,123,161,137 --udp

# Deep TLS/certificate audit
python pentool.py tls example.com

# Web security audit
python pentool.py web https://example.com

# DNS + subdomain recon, including certificate transparency logs
python pentool.py recon example.com --ct

# Fingerprint services and look up CVEs on the National Vulnerability Database
python pentool.py vuln 192.168.1.10 --cve

# Skip the authorization prompt in a lab/CI context
python pentool.py scan 127.0.0.1 --yes
```

Global flags (`-y/--yes`, `-o/--output`) work **before or after** the subcommand.
Full option tables for every command are in **[WIKI.md](WIKI.md)**.

## Reports

Every command accepts `-o report.json` to write machine-readable output. The JSON
contains the tool name, target spec, UTC start time, and a list of findings, each
with `target`, `category`, `title`, `severity` (`info`→`critical`), `detail`, and a
structured `data` object. Terminal output is a severity-sorted summary.

## Design notes

- **No raw sockets.** Port scanning uses TCP connect, so it needs no elevated
  privileges and no packet-crafting library — portable across Kali and Windows.
- **Non-intrusive web checks.** The `web` module only issues `GET`/`HEAD`
  requests; it never attempts exploitation.
- **Optional network calls.** `crt.sh` (recon `--ct`) and NVD (vuln `--cve`) are
  opt-in; everything else stays local to your test path.
- **Authorization gate.** Every run confirms authorization before touching a target.

## Project layout

```
pentool.py              # convenience launcher (python pentool.py ...)
pentool/
  cli.py                # argparse dispatcher + authorization gate
  common.py             # shared helpers: auth, output, target/port parsing, Report model
  scanners/
    network.py          # TCP connect scan + banner grabbing
    web.py              # TLS / header / cookie / exposed-path audit
    recon.py            # DNS, reverse DNS, subdomain brute force, crt.sh
    vuln.py             # fingerprinting, risky-exposure flags, NVD CVE lookup
```

## Legal & ethics

This project is for **authorized engagements**, **security labs**, and
**defensive self-audits** only. Unauthorized scanning or testing of systems you
do not own or control may be illegal in your jurisdiction. You are responsible
for how you use it. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Anthony Ponder
