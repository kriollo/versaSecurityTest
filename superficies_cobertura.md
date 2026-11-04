# Cobertura de servidores, lenguajes y frameworks (secciones 4.x y 5 del catálogo)

`versaSecurity` es un escáner de **caja negra** (HTTP in/out, sin código fuente). Por eso la cobertura
se organiza en dos planos:

## 1. Clases de vulnerabilidad = independientes del lenguaje

Las clases explotables por HTTP (inyección SQL/NoSQL/XPath/LDAP/command, XSS, SSRF, SSTI, XXE, path
traversal, deserialización, CSRF, CORS, request smuggling, etc.) se prueban igual sea PHP, Python, Node,
Go o Java: se envía el payload y se mide la respuesta. **No hay un test "de PHP" vs "de Python"**: el
mismo test cubre todas. Esta parte está ✅ (ver `catalogo_cobertura.md` y `owasp_top10_cobertura.md`).

## 2. Señales específicas de servidor / lenguaje / framework (sí diferencian) → ✅ alcanzable

| Superficie | Qué se detecta | Test |
|---|---|---|
| Apache | `mod_status` (/server-status), `mod_info` (/server-info) | checkFrameworkSurfaces |
| nginx | stub_status (/nginx_status, /status) | checkFrameworkSurfaces |
| Traefik | dashboard y API (/dashboard/, /api/rawdata) | checkFrameworkSurfaces |
| HAProxy | página de stats | checkFrameworkSurfaces |
| Java / Spring Boot | Actuator (/actuator, /actuator/env → config, /actuator/health) | checkFrameworkSurfaces |
| Python / Flask | consola Werkzeug (/console), Django debug toolbar | checkFrameworkSurfaces |
| Go | pprof (/debug/pprof/), expvar (/debug/vars) | checkFrameworkSurfaces |
| PHP / Symfony / Laravel | Profiler (/_profiler), Telescope, phpinfo() | checkFrameworkSurfaces + checkDebugEndpoints |
| Node | source maps, node_modules en errores | checkSecretsInJS + info_disclosure |
| Observabilidad | métricas Prometheus (/metrics) | checkFrameworkSurfaces |
| Fuga de errores por lenguaje | PHP, Python, Go, Node, Java/Servlet, Rails, ASP.NET | info_disclosure (firmas de stack trace) |
| Banner/versión de servidor | header `Server`, `X-Powered-By`, `X-AspNet-Version` | info_gathering, info_disclosure |
| Fingerprint de CMS | WordPress (+plugins con versión), Drupal | checkWordPress, checkDrupal |

## 3. Lo que NO es alcanzable por caja negra (y por qué) → ❌

- **Nivel código fuente (sección 5):** usar `eval`/`pickle`/`unserialize`/`child_process`/`math/rand`
  sin validación. Es análisis estático (SAST): requiere el código, no el tráfico HTTP. El escáner solo
  ve el **resultado** si llega a ser explotable (y eso sí se prueba: command injection, SSTI, deserialización…).
- **Fallos internos del servidor/proxy:** errores de buffer/memoria en Apache/nginx/IIS, bugs del parser
  HTTP. Solo se confirman con fuzzing agresivo o la versión exacta + CVE, no con un escaneo seguro.
- **Logging y alertas (A09):** requiere acceso a los registros del servidor.

## Resumen

Sí: la cobertura abarca PHP, Python, Node, Go, Java y los servidores Apache/nginx/Traefik/HAProxy/Spring,
**en todo lo que un escáner externo puede observar** (clases explotables + superficies y errores expuestos).
Lo que queda fuera es, por definición, código fuente o internals del servidor, que necesitan SAST o la
versión exacta contra una base de CVE — no un escaneo de caja negra.
