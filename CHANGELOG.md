# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2026-10-03

### Added

- **Resiliencia ante DoS (`versaSecurity flood`)**: flujo intenso desde muchas IP (X-Forwarded-For rotado)
  que mide si el rate limiting contiene el abuso (429) o la app se degrada (5xx/timeouts); veredicto e informe JSON.
- **Test `known_vulns`**: detección de solo lectura de las vulnerabilidades de 2026 en frameworks PHP
  (CVE-2026-114509 cookie no-string, -46634 SSTI, -119977 ejecución de .php, exposición de config/.env/vendor).
  Seleccionable también en el modo TUI.
- **Self-update real (`-update`)**: además de avisar de una versión nueva, descarga el binario del release
  que corresponde al sistema (SO/arquitectura) y reemplaza el ejecutable en marcha (seguro en Windows).

### Fixed

- **OutdatedComponents daba falsos positivos**: marcaba WordPress/Drupal/phpMyAdmin con solo un 200, sin
  comprobar el patrón en el cuerpo (un catch-all SPA los disparaba todos). Ahora exige el patrón.
- **DataIntegrity no detectaba cookies serializadas reales**: no decodificaba el valor URL-encoded. Ahora sí.
- **Authentication marcaba `/admin` como panel expuesto**: es la página de login propia de muchos frameworks; se quitó.
- **El release compilaba con `go build main.go`**: ignoraba `load_cmd.go`/`flood_cmd.go` y habría fallado; ahora compila el paquete completo (`.`).
- Cobertura de tests para extractHost, getServiceName, containsVersion, serialización PHP y los fixes anteriores.

- **Prueba de capacidad (`versaSecurity load`)**: usuarios virtuales concurrentes, cada uno con sus cookies,
  su usuario (CSV) y su IP en `X-Forwarded-For`, que inician sesión con token CSRF y recorren rutas
  mientras la carga sube por etapas. Reporta req/s, p50/p95/p99, errores por estado y la capacidad
  estimada según umbrales; guarda el informe JSON en `reports/`.

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
