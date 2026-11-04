# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.1] - 2026-11-03

### Fixed

- **TUI sin corrupción**: el progreso del escáner ya no escribe directamente en stdout, por lo que
  desaparecen las líneas duplicadas y mezcladas (`Hilos: 8los: 8`). El progreso real se transmite a
  la interfaz mediante un canal y se refresca con Bubble Tea.
- **Versión en la UI**: se elimina el valor fijo `v1.3.0`. La versión se toma del build
  (`-ldflags`) o de la metadata VCS, y en compilaciones locales se muestra como `dev-<commit>`
  en lugar de una pseudo-versión larga.

## [2.2.0] - 2026-11-03

### Added

- **Cobertura ampliada del catálogo**: RCE, LFI con wrappers `php://`/`data://`, deserialización PHP,
  RFI, LDAP Injection, CRLF, XXE, Host Header Injection, ReDoS, cache poisoning, mass assignment,
  prototype pollution, JWT, rate limit bypass, WebSocket auth, auth bypass, weak password y GraphQL abuse.
- **Sondas de bajo impacto**: HTTP Request Smuggling (CL vs CL+TE), race conditions, exposición de
  manifiestos/CI (supply chain), entropía de sesión y superficie DoS.
- **Documentación de cobertura**: `catalogo_cobertura.md`, `owasp_top10_cobertura.md` y `php_cobertura.md`.

### Fixed

- **Directory Traversal**: sin falsos positivos por patrones genéricos en respuestas 404.
- **Enumeración de directorios**: `/admin` se reporta como hallazgo.

## [2.1.2] - 2026-11-03

### Added

- **Más vulnerabilidades conocidas**: backups de BD/config, repositorio Git/SVN expuesto, `phpinfo()`,
  `server-status`, documentación OpenAPI/Swagger, endpoints de depuración, listado de directorios y
  introspection de GraphQL.

### Fixed

- **Directory Traversal**: eliminados falsos positivos por patrones genéricos ("ubuntu", etc.) en páginas de
  error 404; solo se reporta con respuesta exitosa.
- **Enumeración de directorios**: se restauró `/admin` como hallazgo reportable.

## [2.1.1] - 2026-11-03

### Fixed

- **Auto-update del binario instalado**: `-update` ahora descarga e instala la nueva versión en lugar de
  mostrar "Próximamente: Actualización automática del binario." El binario instalado se actualizó a v2.1.0
  y se verificó el flujo completo de self-update.

## [2.1.0] - 2026-11-03

### Added

- **Resiliencia ante DoS (`versaSecurity flood`)**: flujo intenso desde muchas IP (X-Forwarded-For rotado)
  que mide si el rate limiting contiene el abuso (429) o la app se degrada (5xx/timeouts); veredicto e informe JSON.
- **Test `known_vulns`**: detección de solo lectura de las vulnerabilidades de 2026 en frameworks PHP
  (CVE-2026-114509 cookie no-string, -46634 SSTI, -119977 ejecución de .php, exposición de config/.env/vendor).
  Seleccionable también en el modo TUI.
- **Self-update real (`-update`)**: además de avisar de una versión nueva, descarga el binario del release
  que corresponde al sistema (SO/arquitectura) y reemplaza el ejecutable en marcha (seguro en Windows).

### Changed

- **Backoff ante 429 (rate limiting) en el cliente HTTP compartido**: si un test (fuerza bruta, API, etc.)
  dispara el límite de peticiones, el escáner espera (respetando `Retry-After`) y reintenta, para que la web
  se desbloquee y los demás tests sigan con respuestas reales en vez de una cascada de 429.
- **Interpretación unificada de códigos HTTP** (`IsRateLimited`/`IsAccessible`/`IsAuthBlocked`/`IsNotFound`):
  un 429 ya nunca se interpreta como hallazgo; "accesible" es solo 2xx.

### Fixed

- **Authorization: un 200 en /admin se marcaba como "bypass"**, pero es la página de login. Ahora solo se
  marca un 200 con contenido que NO sea una pantalla de login; 429/401/403/404 no son hallazgo.
- **SQL avanzado (boolean-blind) marcaba cualquier 404/403 como vulnerable** (`|| statusCode==404`). Reescrito:
  compara una condición verdadera (1=1) vs falsa (1=2), ambas 2xx; solo si verdadero≈base y falso difiere.
- **SQL avanzado (time-based) se disparaba por lentitud del servidor o el backoff**. Ahora usa una petición
  de control: solo marca si el control es rápido y el payload con SLEEP tarda notablemente más.
- **Client-Side: "DOM XSS accesible" por un 200 en una URL con fragmento (#)**: el fragmento no llega al
  servidor. Reemplazado por XSS reflejado real (el payload vuelve sin escapar en la respuesta).
- **HTTP Headers exigía HSTS sobre HTTP** (solo aplica a HTTPS) y fallaba por X-XSS-Protection (obsoleto): ahora informativos.
- **Authentication marcaba falta de `autocomplete=off`** (consejo obsoleto que OWASP desaconseja): eliminado.
- **File Upload reportaba "no hay formularios" como Warning/High**: ahora es informativo (Passed/Info).
- **Information Disclosure marcaba por palabras sueltas** ("error", "admin", "password"): ahora exige firmas
  de fuga reales (stack traces, errores de framework, rutas del servidor).
- **API: CORS `*` se marcaba como riesgo**; `*` solo es inseguro con `Allow-Credentials: true`. Y la inyección
  en API exige una firma de error de BD real, no un 500 genérico. 429 nunca concluye nada.

- **SQL Injection marcaba un 404 normal como vulnerable**: bastaba con que la respuesta contuviera el
  texto "sql" o diera 500. Ahora exige una firma de error de base de datos real (igual que el test avanzado).
- **Métodos HTTP: un 400/404 se reportaba como "método peligroso habilitado"** (p. ej. TRACK con 400).
  Un método solo es "habilitado" si el servidor lo acepta (2xx). Corregido en el test de métodos y en Configuration.
- **Configuration marcaba `/admin`, `/dashboard`, `/panel`… como "ruta interna expuesta"**: son entradas
  públicas normales (login). Ahora solo se revisan rutas de depuración/entornos (debug, test, staging, metrics,
  actuator) y únicamente con status 200.
- **Session Management daba siempre falso positivo de fijación**: comparaba el ID entre dos GET anónimos
  esperando que cambiara (no debe). Ahora hace la prueba correcta sin login: ver si el servidor adopta un ID
  elegido por el cliente en vez de emitir el suyo (severidad Low).
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
