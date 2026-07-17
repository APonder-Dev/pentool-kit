# Changelog

All notable changes to **pentool** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.3] - 2026-07-17

### Added
- README badge row: CI status, PyPI version, supported Python versions, MIT
  license, GHCR container, and platforms.

No functional changes to the toolkit.

## [1.1.2] - 2026-07-17

### Added
- `CHANGELOG.md` following Keep a Changelog / SemVer, documenting all releases,
  linked from the README.

### Changed
- `RELEASING.md`: the release checklist now includes a step to update the
  changelog alongside the version bump.

No functional changes to the toolkit.

## [1.1.1] - 2026-07-17

### Changed
- Updated GitHub Actions to their current major versions (Node 24 runtimes),
  clearing the Node 20 deprecation warnings in CI and release workflows:
  `checkout` v4→v7, `setup-python` v5→v6, `upload-artifact` v4→v7,
  `download-artifact` v4→v8, `softprops/action-gh-release` v2→v3,
  `docker/login-action` v3→v4, `docker/metadata-action` v5→v6,
  `docker/build-push-action` v6→v7.

No functional changes to the toolkit.

## [1.1.0] - 2026-07-16

### Added
- `tls` command: deep TLS/SSL audit — probes SSLv3/TLSv1.0–1.3 support, checks
  certificate trust (expired / self-signed / hostname mismatch), and reports
  subject, issuer, SANs, and expiry (with severity by days remaining).
- `scan --udp`: connected-UDP probing with protocol-specific payloads for DNS,
  NTP, SNMP, and NetBIOS; reports `open` / `open|filtered`.
- `scan --discover`: TCP ping-sweep that scans only hosts that are up.
- Report export formats via `-f/--format` (`json`, `html`, `md`, `csv`), also
  inferred from the `-o` file extension. Styled, severity-colored HTML output.

### Changed
- Network-scan reports are tagged `network-scan-tcp` / `network-scan-udp`.

## [1.0.0] - 2026-07-15

### Added
- Initial release of the cross-platform (Kali Linux / Windows) authorized
  penetration-testing & self-audit toolkit. Pure standard-library core.
- `scan`: threaded TCP connect port scan with banner grabbing (no root/admin).
- `web`: web audit — TLS version, security headers, cookie flags, and exposed
  sensitive paths (GET/HEAD only, non-intrusive).
- `recon`: DNS records, reverse DNS, subdomain brute force, and optional crt.sh
  certificate-transparency lookup.
- `vuln`: service fingerprinting, risky-exposure flagging, and optional NVD CVE
  lookup.
- Authorization gate on every run (`--yes` / `PENTOOL_AUTHORIZED=1` to bypass).
- JSON reporting, packaging (PyPI `pentool-kit`), container image (GHCR), CI, and
  tag-triggered release automation.

[1.1.3]: https://github.com/APonder-Dev/pentool-kit/releases/tag/v1.1.3
[1.1.2]: https://github.com/APonder-Dev/pentool-kit/releases/tag/v1.1.2
[1.1.1]: https://github.com/APonder-Dev/pentool-kit/releases/tag/v1.1.1
[1.1.0]: https://github.com/APonder-Dev/pentool-kit/releases/tag/v1.1.0
[1.0.0]: https://github.com/APonder-Dev/pentool-kit/releases/tag/v1.0.0
