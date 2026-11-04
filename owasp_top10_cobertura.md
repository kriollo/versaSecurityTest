# Cobertura OWASP Top 10 (2021)

Mapeo entre las categorías OWASP Top 10 2021 y los tests implementados en `versaSecurity`.

| Categoría | Nombre | Estado | Test(s) existente(s) | Notas |
|---|---|---|---|---|
| A01:2021 | Broken Access Control | ✅ | Authorization, ATHZ-01, ATHZ-04, Known Vulnerabilities (unauth admin) | |
| A02:2021 | Cryptographic Failures | ✅ | CRYP-01, SSL/TLS Analysis | HTTPS, cookies, cifrado |
| A03:2021 | Injection | ✅ | SQL Injection, Advanced SQL Injection, XSS, Advanced XSS, Command Injection, LDAP, XXE, SSTI | Cobertura amplia |
| A04:2021 | Insecure Design | 🟡 | Business Logic Testing, Known Vulnerabilities (business logic) | Parcial |
| A05:2021 | Security Misconfiguration | ✅ | Configuration Security, CONF-06, Advanced Security Headers | CORS, headers, páginas por defecto |
| A06:2021 | Vulnerable and Outdated Components | ✅ | A06:2021 - Vulnerable and Outdated Components | Banners/versiones |
| A07:2021 | Identification and Authentication Failures | ✅ | ATHN-01, Brute Force Test, IDNT-01, IDNT-05 | Login, fuerza bruta, enumeración |
| A08:2021 | Software and Data Integrity Failures | ✅ | A08:2021 - Software and Data Integrity Failures | Deserialización/integridad |
| A09:2021 | Security Logging and Monitoring Failures | ❌ | - | No automatizable externamente |
| A10:2021 | Server-Side Request Forgery (SSRF) | ✅ | Server-Side Request Forgery (SSRF) | |

Leyenda:
- ✅ Implementado
- 🟡 Parcial
- ❌ No automatizable externamente / faltante
