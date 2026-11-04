# Cobertura del catálogo de vulnerabilidades web

Mapeo entre el catálogo `catalogo_vulnerabilidades_web.md` (WEB-001..WEB-050)
y los tests implementados en `versaSecurity`.

Leyenda:
- ✅ Implementado: existe test dinámico que busca la clase.
- 🟡 Parcial: existe cobertura indirecta o limitada.
- ❌ Faltante: no hay test específico.

| ID | Vulnerabilidad | Estado | Test(s) existente(s) | Notas |
|---|---|---|---|---|
| WEB-001 | SQL Injection | ✅ | SQL Injection, Advanced SQL Injection | Incluye blind/time-based |
| WEB-002 | Cross-Site Scripting (XSS) | ✅ | Cross-Site Scripting (XSS), Advanced XSS | Reflejado/DOM |
| WEB-003 | CSRF | ✅ | CSRF Protection | Tokens, SameSite, CORS |
| WEB-004 | SSRF | ✅ | Server-Side Request Forgery (SSRF) | |
| WEB-005 | RCE | ✅ | Known Vulnerabilities (RCE, command injection) | |
| WEB-006 | LFI | ✅ | Directory Traversal, Advanced, PHP wrappers | |
| WEB-007 | RFI | ❌ | - | Implementar include remoto |
| WEB-008 | Path Traversal | ✅ | Directory Traversal, Advanced Directory Traversal | |
| WEB-009 | Broken Access Control | ✅ | Authorization, ATHZ-01, ATHZ-04, Known Vulnerabilities (unauth admin, auth bypass) | |
| WEB-010 | IDOR / BOLA | ✅ | ATHZ-04: Direct Object Reference Testing | |
| WEB-011 | Authentication Bypass | ✅ | ATHN-01, Known Vulnerabilities (auth bypass) | |
| WEB-012 | Session Fixation | ✅ | Session Management | |
| WEB-013 | Session Hijacking | ✅ | Session Management, Known Vulnerabilities (flags, entropy) | |
| WEB-014 | Open Redirect | ✅ | Open Redirect | |
| WEB-015 | HTTP Response Splitting | 🟡 | Known Vulnerabilities (CRLF) | Parcial |
| WEB-016 | CRLF Injection | ✅ | Known Vulnerabilities (CRLF) | |
| WEB-017 | OS Command Injection | ✅ | Known Vulnerabilities (command injection) | |
| WEB-018 | LDAP Injection | ✅ | Known Vulnerabilities (LDAP) | |
| WEB-019 | XXE | ✅ | Known Vulnerabilities (XXE) | |
| WEB-020 | Insecure Deserialization | ✅ | A08:2021 - Software and Data Integrity Failures | |
| WEB-021 | SSTI | ✅ | Known Vulnerabilities (template injection) | |
| WEB-022 | Unrestricted File Upload | ✅ | File Upload Test | |
| WEB-023 | Information Disclosure | ✅ | Information Disclosure, INFO-06 | |
| WEB-024 | Security Misconfiguration | ✅ | Configuration Security, CONF-06 | |
| WEB-025 | Missing Security Headers | ✅ | Advanced Security Headers Test, HTTP Headers Test | |
| WEB-026 | Clickjacking | ✅ | Advanced Security Headers (X-Frame-Options) | |
| WEB-027 | Cryptographic Failures | ✅ | CRYP-01, SSL/TLS Analysis | |
| WEB-028 | Weak Password Policy | ✅ | IDNT-01, Known Vulnerabilities (weak password) | |
| WEB-029 | Brute Force / Credential Stuffing | ✅ | Brute Force Test | |
| WEB-030 | DoS | 🟡 | Known Vulnerabilities (burst probe), flood | Sonda básica |
| WEB-031 | ReDoS | ✅ | Known Vulnerabilities (ReDoS) | |
| WEB-032 | Cache Poisoning | ✅ | Known Vulnerabilities (Cache Poisoning) | |
| WEB-033 | HTTP Request Smuggling | 🟡 | Known Vulnerabilities (CL+TE probe) | Sonda de bajo impacto |
| WEB-034 | Race Condition | 🟡 | Known Vulnerabilities (concurrency probe), flood | Sonda básica |
| WEB-035 | Mass Assignment | ✅ | Known Vulnerabilities (Mass Assignment) | |
| WEB-036 | Prototype Pollution | ✅ | Known Vulnerabilities (Prototype Pollution) | |
| WEB-037 | CORS Misconfiguration | ✅ | Configuration Security, CSRF Protection | |
| WEB-038 | JWT Validation Failure | ✅ | Known Vulnerabilities (JWT) | |
| WEB-039 | Rate Limit Bypass | 🟡 | Known Vulnerabilities (Rate Limit) | Informativo |
| WEB-040 | Secrets Exposure | ✅ | Known Vulnerabilities (archivos sensibles, JS bundles) | |
| WEB-041 | Dependency Vulnerability | ✅ | A06: Vulnerable and Outdated Components | |
| WEB-042 | Dependency Confusion | 🟡 | Known Vulnerabilities (manifiestos expuestos) | Solo exposición |
| WEB-043 | Supply Chain Compromise | 🟡 | Known Vulnerabilities (CI/manifiestos expuestos) | Solo exposición |
| WEB-044 | Host Header Injection | ✅ | Known Vulnerabilities (Host header) | |
| WEB-045 | DNS Rebinding | 🟡 | Known Vulnerabilities (Host header) | Indirecto |
| WEB-046 | WebSocket Authorization Failure | ✅ | Known Vulnerabilities (WebSocket) | |
| WEB-047 | GraphQL Abuse | ✅ | Known Vulnerabilities (introspection, depth) | |
| WEB-048 | TLS Misconfiguration | ✅ | SSL/TLS Analysis | |
| WEB-049 | Improper Error Handling | ✅ | ERRH-01: Error Leakage Testing | |
| WEB-050 | Insufficient Logging and Alerting | ❌ | - | No automatizable externamente |

## Prioridad sugerida de implementación
1. WEB-017 OS Command Injection
2. WEB-019 XXE
3. WEB-016 CRLF Injection
4. WEB-044 Host Header Injection
5. WEB-038 JWT Validation
6. WEB-007 RFI
7. WEB-015 HTTP Response Splitting
8. WEB-037 ya cubierto; WEB-047 ampliar GraphQL
