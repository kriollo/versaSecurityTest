# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-02

### Added

- **OWASP Top 10 2021 Integration**:
  - New module `A06: Vulnerable and Outdated Components` for software fingerprinting.
  - New module `A08: Software and Data Integrity Failures` for insecure deserialization checks.
  - Enhanced module `A10: SSRF` with advanced bypasses (Octal IP, IPv6, Dotted Decimal).
- **Network Port Scanning**:
  - Concurrent TCP port scanner (`NETW-01`) identifying 20+ common services.
- **TUI Granular Navigation**:
  - Support for `Backspace/B` to go back to test selection.
  - Support for `P` to go back to profile selection.
  - Support for `Enter` to retry scan from results screen.
  - Support for `Ctrl+R` for full reset.
- **Granular Test Selection**: Individual toggles for the new OWASP and Network modules in the UI.

### Changed

- Refactored `scanner.go` to use precise configuration flags for each new module.
- Updated `README.md` and Roadmap for v2.0.0.
- Improved naming logic in reports for better readability.

### Fixed

- Issue where certain banners were ignored by the security scanner.
- Improved handling of 429 Rate Limit responses during header analysis.

## [1.3.0] - 2026-02-02

### Added

- GitHub Actions CI/CD for automated releases.
- TUI Porting with per-test progress indicators.
- Scan Profiles (Basic, Standard, Advanced).
- Advanced XSS and Directory Traversal implementations.

## [1.2.0] - 2025-12-15

- Initial TUI implementation.
- Basic scanner engine convergence.

## [1.1.0] - 2025-10-10

- Added JSON and Table reporting formats.

## [1.0.0] - 2025-09-01

- Project start: Basic connectivity and header tests.
