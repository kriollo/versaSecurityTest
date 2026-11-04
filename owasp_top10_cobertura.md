# Cobertura OWASP Top 10 (2025)

Mapeo entre las categorías OWASP Top 10 2025 (las que usa `catalogo_vulnerabilidades_web.md`)
y los tests implementados en `versaSecurity`.

| Categoría | Nombre | Estado | Test(s) existente(s) | Notas |
|---|---|---|---|---|
| A01:2025 | Broken Access Control | ✅ | Authorization (ATHZ-01), Direct Object Reference (ATHZ-04), Known Vulnerabilities (admin sin auth, auth bypass) | Objeto, función, tenant |
| A02:2025 | Security Misconfiguration | ✅ | Configuration Security, CONF-06, Advanced Security Headers, HTTP Methods | CORS, headers, defaults, métodos |
| A03:2025 | Software Supply Chain Failures | 🟡 | A06 Componentes, Known Vulnerabilities (manifiestos/CI expuestos) | Se detecta exposición; dependency confusion/pipeline exige datos internos |
| A04:2025 | Cryptographic Failures | ✅ | CRYP-01, SSL/TLS Analysis, Known Vulnerabilities (entropía de sesión) | HTTPS, TLS, cookies, aleatoriedad |
| A05:2025 | Injection | ✅ | SQL (+ avanzado ciego), XSS (+ avanzado), OS Command, LDAP, **NoSQL**, **XPath**, SSTI, XXE, CRLF | Cobertura amplia de intérpretes |
| A06:2025 | Insecure Design | 🟡 | Business Logic Testing, Known Vulnerabilities (business logic) | Límite inherente: el diseño no se audita por caja negra |
| A07:2025 | Authentication Failures | ✅ | ATHN-01, Brute Force, IDNT-01/05, Session Management, Known Vulnerabilities (JWT, fijación, hijacking) | Login, fuerza bruta, sesiones, MFA observable |
| A08:2025 | Software or Data Integrity Failures | ✅ | A08 Integridad, Known Vulnerabilities (deserialización PHP, prototype pollution) | Serialización/integridad |
| A09:2025 | Security Logging and Alerting Failures | ❌ | - | No automatizable externamente (requiere los registros del servidor) |
| A10:2025 | Mishandling of Exceptional Conditions | 🟡 | ERRH-01 (fuga en errores), Known Vulnerabilities (superficie DoS, race condition) | Se detecta fuga/5xx bajo estado anómalo; agotamiento de recursos no se fuerza por seguridad |

Leyenda:
- ✅ Implementado: existe test dinámico que busca la clase.
- 🟡 Parcial: se detecta la superficie, pero confirmar la explotación excede el escaneo de caja negra.
- ❌ No automatizable externamente.
