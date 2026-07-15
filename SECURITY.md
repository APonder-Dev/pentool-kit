# Security Policy & Acceptable Use

`pentool` is a security-testing toolkit. It is built for **authorized penetration
testing**, **security labs/CTFs**, and **defensive self-audits**. This document
covers acceptable use, the tool's safety design, and how to report a vulnerability
in the tool itself.

---

## Acceptable use

**You may use pentool only against systems that you own or for which you hold
explicit, written authorization to test.**

Appropriate contexts:

- Penetration-testing engagements with a signed scope/authorization document.
- Isolated lab environments and CTF challenges you are entitled to attack.
- Auditing and hardening infrastructure you own or operate.

**Do not** use pentool to scan, probe, fingerprint, or query third-party systems
without permission. Unauthorized scanning may violate laws such as the U.S.
Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, the EU
directives on attacks against information systems, and equivalents worldwide —
including in many cases mere port scanning. **You are solely responsible for how
you use this tool and for confirming your authorization and legal standing.**

The authors provide this software "as is" and accept no liability for misuse.
See [LICENSE](LICENSE).

---

## Scope of "authorization" — a checklist

Before running against any target, confirm:

- [ ] The target hosts/domains/IP ranges are explicitly in scope, in writing.
- [ ] The testing window (dates/times) is agreed.
- [ ] Outbound lookups are acceptable if you use `recon --ct` (crt.sh) or
      `vuln --cve` (NVD) — these send the target domain/product strings to a
      third party.
- [ ] You have a point of contact for the target owner in case of impact.

---

## Safety design of the tool

pentool is intentionally conservative:

- **No privilege escalation, no raw packets.** Scanning uses TCP connect only, so
  it never needs root/Administrator or a packet-crafting library.
- **Non-intrusive web checks.** The `web` module issues only `GET`/`HEAD`
  requests. It does **not** attempt injection, brute force, or exploitation.
- **No exploitation in `vuln`.** The vuln module fingerprints services and flags
  known-risky exposures; it does not launch exploits. CVE data is informational.
- **Opt-in outbound calls.** The only third-party network calls are `recon --ct`
  (crt.sh) and `vuln --cve` (NVD). Everything else stays on your test path.
- **Authorization gate.** Every invocation requires an authorization confirmation
  (interactive prompt, `--yes`, or `PENTOOL_AUTHORIZED=1`).

> The authorization gate is an operator-intent checkpoint, **not** an access
> control. It does not and cannot verify that you are actually authorized.

---

## Responsible operation

- Prefer the smallest scope and lowest intensity that meets your goal
  (`--no-banner`, `--no-paths`, `--no-brute`, targeted `-p` lists, lower `-w`).
- Rate-limit yourself on fragile or production targets; large CIDR sweeps with
  high worker counts can stress hosts and network gear.
- Store JSON reports securely — they may contain sensitive details about the
  target's exposure.
- Do not commit real report files to version control (the repo `.gitignore`
  excludes `*.json` by default).

---

## Reporting a vulnerability in pentool

If you discover a security issue in **pentool itself** (for example, a way it could
be tricked into acting outside its stated scope, or a code-execution/path issue in
the tooling), please report it privately:

- **Email:** Anthony@aponder.dev
- **Subject:** `pentool security report`

Please include a description, reproduction steps, affected version
(`python pentool.py --version`), and platform. Allow a reasonable window for a fix
before any public disclosure. Do not include live third-party target data in your
report.

There is no bug bounty; this is a personal/educational project. Good-faith reports
are appreciated and credited if you wish.

---

## Supported versions

This is an actively developed 1.x project; fixes land on the latest version.
Report against the version shown by `python pentool.py --version`.
