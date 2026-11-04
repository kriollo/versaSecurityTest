# Cobertura: 4.2 PHP y frameworks PHP

Mapeo entre los riesgos listados en el catálogo (sección 4.2) y los tests
implementados en `versaSecurity`.

| Tecnología / Superficie | Clase de riesgo | Estado | Test(s) existente(s) | Notas |
|---|---|---|---|---|
| PHP Runtime | RCE | ✅ | Known Vulnerabilities (RCE, command injection) | |
| PHP Runtime | File inclusion / path traversal | ✅ | Directory Traversal, Advanced Directory Traversal, Known Vulnerabilities (PHP wrappers) | |
| PHP Runtime | Deserialización | ✅ | A08 + Known Vulnerabilities (PHP deserialization) | |
| PHP Runtime | Command injection | ✅ | OS Command Injection | |
| PHP Runtime | Exposición de configuración | ✅ | Known Vulnerabilities (archivos sensibles) | |
| Laravel | SQLi / XSS / CSRF / mass assignment / upload / path traversal / tokens | ✅/🟡 | SQL/XSS/CSRF/File Upload/Dir Traversal/Mass Assignment | Cobertura genérica |
| Symfony | Autorización, autenticación, SSTI, SSRF, deserialización, parser DoS, cache poisoning, routing | ✅/🟡 | Varios (SSTI, SSRF, deserialization, cache poisoning) | Cobertura genérica |
| CodeIgniter / CakePHP / Yii / Laminas / Slim / Phalcon | SQLi, XSS, CSRF, sesión, upload, autorización, deserialización | ✅/🟡 | Tests genéricos equivalentes | Cobertura genérica |
| WordPress | XSS, SQLi, CSRF, escalada, upload, plugins | 🟡 | Known Vulnerabilities (CVE 2026 PHP, WordPress) | Detección básica de WP y superficies |
| Drupal | RCE, XSS, SQLi, bypass de acceso, upload, dependencias | 🟡 | Conocidos + A06 + Drupal | Detección básica |
| TYPO3 | RCE, XSS, SQLi, auth, autorización, exposición | 🟡 | Genéricos | Cobertura básica |

## Pendientes específicos de PHP
- Wrappers LFI (`php://filter`, `data://`, `phar://`).
- Deserialización PHP (`unserialize`) con cadenas maliciosas.
- Funciones peligrosas (`eval`, `assert`, `preg_replace /e`, `create_function`).
- Exposición de `composer.json`/`vendor` (ya parcial).
- Detección de plugins/themes vulnerables de WordPress/Drupal.
