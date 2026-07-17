# pentool — Wiki & Reference

Full reference for every command, flag, output field, and internal behavior.
For a quick start see [README.md](README.md); for acceptable use see [SECURITY.md](SECURITY.md).

---

## Table of contents

1. [Concepts](#1-concepts)
2. [Global options](#2-global-options)
3. [Authorization gate](#3-authorization-gate)
4. [`scan` — port scanner](#4-scan--port-scanner)
5. [`web` — web audit](#5-web--web-audit)
6. [`recon` — DNS & subdomains](#6-recon--dns--subdomains)
7. [`vuln` — fingerprint & CVE](#7-vuln--fingerprint--cve)
8. [`tls` — TLS/SSL deep audit](#8-tls--tlsssl-deep-audit)
9. [Report formats](#9-report-formats)
10. [Severity levels](#10-severity-levels)
11. [Target & port syntax](#11-target--port-syntax)
12. [Exit codes](#12-exit-codes)
13. [Platform notes](#13-platform-notes-kali--windows)
14. [Extending pentool](#14-extending-pentool)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Concepts

`pentool` is a single CLI dispatching to five scanner modules. Each module builds a
`Report` object (a list of `Finding` records), prints a severity-sorted summary to
the terminal, and optionally writes the full report to JSON.

Everything in the core relies only on the Python standard library, so no packages
are needed to run. Two features make **opt-in** outbound calls to third parties:
`recon --ct` (crt.sh) and `vuln --cve` (NVD API).

Invocation forms are equivalent:

```bash
python pentool.py <command> [args]     # launcher script
python -m pentool.cli <command> [args] # module form
pentool <command> [args]               # after `pip install -e .`
```

---

## 2. Global options

These apply to all commands and may appear **before or after** the subcommand:

| Flag | Description |
|------|-------------|
| `-y`, `--yes` | Skip the interactive authorization prompt (for labs/CI). |
| `-o FILE`, `--output FILE` | Write the full findings report to `FILE`. |
| `-f`, `--format` | Report format: `json`, `html`, `md`, `csv`. Default: inferred from the `-o` extension, else `json`. |
| `--version` | Print version and exit. |
| `-h`, `--help` | Show help. Works per-subcommand too (`pentool scan -h`). |

The environment variable `PENTOOL_AUTHORIZED=1` has the same effect as `--yes`.
`NO_COLOR=1` disables ANSI colors (colors also auto-disable when output is piped).

---

## 3. Authorization gate

Before any command runs, `require_authorization()` checks:

1. `--yes` flag → proceed.
2. `PENTOOL_AUTHORIZED=1` in the environment → proceed.
3. Otherwise → prompt: *"Confirm you have written authorization to test the
   target(s) [y/N]"*. Any answer other than `y`/`yes` aborts with exit code `2`.

This is a deliberate friction point, not a security control. It exists to make the
operator affirm scope on every run. **It does not verify authorization** — that is
your legal responsibility.

---

## 4. `scan` — port scanner

Threaded **TCP connect** scan. Establishes a full TCP handshake per port, so it
requires no elevated privileges and no raw-packet library (works identically on
Kali and Windows). Open ports are optionally banner-grabbed.

```bash
python pentool.py scan <target> [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `target` | (required) | Host, IP, CIDR, or comma-separated list. |
| `-p`, `--ports` | `top` | `top`, a range (`1-1024`), or explicit (`22,80,443`). |
| `-w`, `--workers` | `200` | Concurrent connection threads. |
| `-t`, `--timeout` | `1.0` | Per-port connection timeout in seconds. |
| `--no-banner` | off | Skip banner grabbing (faster, quieter). |
| `--udp` | off | Scan UDP instead of TCP. Results are `open` or `open|filtered` (UDP cannot be probed as reliably as TCP). Known services (DNS, NTP, SNMP, NetBIOS) get a protocol-specific probe payload. |
| `--discover` | off | Run a TCP ping-sweep first and scan only hosts that are up. A host counts as "up" if a probe port accepts **or** actively refuses the connection. Greatly speeds up sparse CIDR ranges. |

**Banner grabbing:** on TLS ports (443, 465, 993, 995, 8443) it negotiates TLS and
reports the protocol version and certificate common name. On common HTTP ports it
sends `HEAD / HTTP/1.0` to elicit a status line. Otherwise it reads up to 256 bytes
of whatever the service announces.

**`top` port set:** a curated ~40-port list of the most common services (FTP, SSH,
SMTP, DNS, HTTP(S), SMB, RDP, databases, Redis, Elasticsearch, MongoDB, etc.).

**Findings:** one `port` finding per open port, severity `info`, with `data`
containing `ip`, `port`, `service`, and `banner`.

Examples:

```bash
python pentool.py scan 192.168.1.10                     # top ports, with banners
python pentool.py scan 10.0.0.0/24 -p 22,80,443 --no-banner
python pentool.py scan example.com -p 1-1024 -t 0.5 -w 400
```

---

## 5. `web` — web audit

Non-intrusive HTTP(S) audit. Issues only `GET`/`HEAD` requests and never attempts
exploitation. TLS certificate verification is intentionally relaxed so the tool can
still audit hosts with self-signed or mismatched certs.

```bash
python pentool.py web <url> [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `url` | (required) | Target URL or host. `http://` is assumed if no scheme. |
| `-t`, `--timeout` | `8.0` | Per-request timeout in seconds. |
| `--no-paths` | off | Skip sensitive-path probing. |

**Checks performed:**

- **TLS version** (https only): flags `SSLv3`, `TLSv1`, `TLSv1.1` as `high`.
- **Security headers** — missing header findings:
  - `Strict-Transport-Security` (HSTS) → `medium`
  - `Content-Security-Policy` → `medium`
  - `X-Frame-Options` → `low`
  - `X-Content-Type-Options` → `low`
  - `Referrer-Policy` → `info`
  - `Permissions-Policy` → `info`
- **Server header** disclosure → `info`.
- **Cookie flags:** missing `HttpOnly` → `low`; missing `Secure` on https → `low`.
- **Exposed paths** (probed concurrently unless `--no-paths`): checks for
  accidentally reachable files such as `/.git/config`, `/.env`, `/wp-config.php`
  (→ `high`), and others like `/server-status`, `/backup.zip`, `/swagger-ui.html`
  (→ `medium`); benign informational ones like `/robots.txt` are `info`.

Examples:

```bash
python pentool.py web https://example.com
python pentool.py web example.com:8080 --no-paths
python pentool.py web https://internal.lab -o web-report.json
```

---

## 6. `recon` — DNS & subdomains

Domain reconnaissance combining active DNS resolution and optional passive
certificate-transparency lookup.

```bash
python pentool.py recon <domain> [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `domain` | (required) | Target domain, e.g. `example.com`. |
| `-w`, `--workers` | `50` | Concurrent resolver threads for brute force. |
| `--no-brute` | off | Skip the subdomain brute force. |
| `--ct` | off | Also query crt.sh certificate transparency logs (outbound). |

**What it collects:**

- **DNS records:** with `dnspython` installed, resolves A, AAAA, MX, NS, TXT, CNAME,
  SOA. Without it, falls back to A/AAAA via the system resolver.
- **Reverse DNS (PTR):** for each resolved IP.
- **Subdomain brute force:** resolves a built-in ~50-word list of common
  subdomains (`www`, `mail`, `vpn`, `api`, `dev`, `staging`, `admin`, …).
- **crt.sh (`--ct`):** pulls names from public CT logs — a passive way to discover
  subdomains that never appear in the wordlist.

All findings are `dns` category, severity `info`.

Examples:

```bash
python pentool.py recon example.com
python pentool.py recon example.com --ct -o recon.json
python pentool.py recon example.com --no-brute      # records only
```

---

## 7. `vuln` — fingerprint & CVE

Heuristic, **non-exploitative** vulnerability surface check. Internally it runs the
`scan` module (with banners) first, then analyzes the results.

```bash
python pentool.py vuln <target> [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `target` | (required) | Host, IP, CIDR, or comma-separated list. |
| `-p`, `--ports` | `top` | Ports to check. |
| `-w`, `--workers` | `200` | Concurrent sockets. |
| `-t`, `--timeout` | `1.5` | Per-port timeout in seconds. |
| `--cve` | off | Query NVD for CVEs matching identified product versions (outbound). |

**What it does:**

- **Risky-exposure flags:** maps open ports to known-risky services. Examples:
  Telnet (`high`), SMB/445 (`high`), RDP/3389 (`high`), NFS/2049 (`high`),
  Docker API/2375 (`critical`), Redis/6379 (`critical`), MongoDB/27017
  (`critical`), Memcached/11211 (`high`), Elasticsearch/9200 (`high`), plus FTP,
  MSSQL, MySQL, PostgreSQL, VNC, etc.
- **Service fingerprinting:** regex-matches banners to identify products and
  versions (OpenSSH, Apache, nginx, IIS, vsftpd, ProFTPD, Exim, Postfix).
- **CVE lookup (`--cve`):** for each versioned product, queries the NVD 2.0
  keyword API and reports matching CVEs with CVSS score and mapped severity.

> The NVD public API is rate-limited (a few requests/minute without an API key),
> so `--cve` can be slow for many products. It is opt-in for this reason.

Examples:

```bash
python pentool.py vuln 192.168.1.10
python pentool.py vuln 192.168.1.10 --cve -o vuln.json
python pentool.py vuln 10.0.0.0/24 -p 22,445,3389,6379
```

---

## 8. `tls` — TLS/SSL deep audit

Deep inspection of a TLS endpoint's protocol support and certificate. Standard
library only.

```bash
python pentool.py tls <target> [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `target` | (required) | `host`, `host:port`, or an `https://` URL. Port defaults to 443. |
| `-t`, `--timeout` | `6.0` | Handshake timeout in seconds. |

**What it checks:**

- **Protocol support:** attempts a handshake pinned to each of SSLv3, TLSv1.0,
  TLSv1.1, TLSv1.2, TLSv1.3. Supported legacy versions are flagged — SSLv3/TLSv1.0
  (`high`), TLSv1.1 (`medium`). Offering no modern (1.2/1.3) protocol is `high`.
- **Certificate trust:** performs a verifying handshake and reports why it fails
  (expired, self-signed, hostname mismatch) as `high`/`medium`.
- **Certificate details:** subject CN, issuer, and Subject Alternative Names —
  read even from untrusted/self-signed certs.
- **Expiry:** days until `notAfter`. Already expired → `critical`; ≤14 days →
  `high`; ≤30 days → `medium`; otherwise `info`.

All findings use the `tls` category.

Examples:

```bash
python pentool.py tls example.com
python pentool.py tls example.com:8443 -o tls.html
python pentool.py tls https://internal.lab
```

> Certificate parsing uses the stdlib `ssl` module. If a certificate cannot be
> decoded on your Python build, the tool still reports protocol support and trust
> status and degrades gracefully on the detail fields.

---

## 9. Report formats

Any command accepts `-o FILE`. The format is chosen by `-f/--format`
(`json`, `html`, `md`, `csv`), or inferred from the file extension, or defaults to
JSON.

| Format | Best for |
|--------|----------|
| `json` | Machine parsing, piping into other tools (full structured `data`). |
| `html` | A shareable, styled, severity-colored report. |
| `md` | Pasting into tickets, PRs, or engagement notes. |
| `csv` | Spreadsheets and quick sorting/filtering. |

```bash
python pentool.py scan 10.0.0.0/24 --discover -o hosts.html      # inferred: html
python pentool.py tls example.com -o cert -f md                  # explicit: markdown
```

HTML/Markdown/CSV are flat summaries (severity, category, target, title, detail).
The **JSON** format additionally includes each finding's structured `data` object:

With `-o report.json` you get:

```json
{
  "tool": "network-scan",
  "target_spec": "192.168.1.10",
  "started": "2026-07-15T18:04:11.123456+00:00",
  "findings": [
    {
      "target": "192.168.1.10",
      "category": "port",
      "title": "22/tcp open (ssh)",
      "severity": "info",
      "detail": "SSH-2.0-OpenSSH_9.6",
      "data": { "ip": "192.168.1.10", "port": 22, "service": "ssh",
                "banner": "SSH-2.0-OpenSSH_9.6" }
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `tool` | Which module produced the report (`network-scan`, `web-scan`, `recon`, `vuln-check`). |
| `target_spec` | The raw target/URL/domain you passed. |
| `started` | UTC ISO-8601 timestamp when the run began. |
| `findings[].category` | `port`, `web`, `dns`, or `vuln`. |
| `findings[].severity` | See below. |
| `findings[].data` | Structured, machine-parseable detail (varies by category). |

---

## 10. Severity levels

Ordered from most to least urgent in summaries:

`critical` → `high` → `medium` → `low` → `info`

`info` findings are neutral facts (an open port, a DNS record, a disclosed
Server header). They are not necessarily problems — context decides.

---

## 11. Target & port syntax

**Targets** (`scan`, `vuln`) accept, comma-separated:

- a single hostname: `example.com`
- a single IP: `192.168.1.10`
- a CIDR range: `10.0.0.0/24` (expands to all usable hosts)
- any mix: `example.com,10.0.0.5,192.168.1.0/28`

**Ports** (`-p`):

- `top` — the built-in common-ports set
- a range — `1-1024`
- explicit — `22,80,443`
- combined — `22,80,8000-8100`

---

## 12. Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed (findings may or may not exist). |
| `1` | Runtime error (surfaced as `[-] Error: ...`). |
| `2` | Authorization not confirmed. |
| `130` | Interrupted (Ctrl-C). |

---

## 13. Platform notes (Kali & Windows)

- **No privileges required.** TCP connect scanning and HTTP(S) requests work as an
  unprivileged user on both platforms — no `sudo`/Administrator, no WinPcap/Npcap.
- **Windows console:** ANSI colors work in Windows Terminal and modern
  PowerShell. Set `NO_COLOR=1` if you see stray escape codes in an old console.
- **Threading:** default worker counts (200 for scans) are conservative and safe on
  both platforms. Increase `-w` for speed on a fast LAN; lower it on flaky links.
- **DNS records:** install `dnspython` (`pip install dnspython`) for full record
  types; otherwise `recon` uses the OS resolver for A/AAAA only.

---

## 14. Extending pentool

To add a new scanner:

1. Create `pentool/scanners/<name>.py` exposing `def run(args) -> Report:`.
2. Build findings with `common.Finding` and append them to a `common.Report`.
3. Register a subparser in `pentool/cli.py` (add it to the `parents=[common]` list
   so it inherits `--yes`/`--output`) and set `func=<name>.run`.

The `Report`/`Finding` model and the summary/JSON output are handled for you.

---

## 15. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `unrecognized arguments: -y` | Update to current version; `-y`/`-o` now work in both positions. |
| Aborts with "Authorization not confirmed" | Answer `y`, pass `--yes`, or set `PENTOOL_AUTHORIZED=1`. |
| `recon` shows only A/AAAA records | Install `dnspython` for MX/NS/TXT/SOA/CNAME. |
| `--cve` is very slow or returns nothing | NVD rate limits unauthenticated requests; retry, or scope to fewer products. |
| No open ports found but you expect some | Increase `-t` (timeout), lower `-w`, or check a host firewall is not dropping SYNs. |
| Stray color codes on Windows | Set `NO_COLOR=1` or use Windows Terminal. |
