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
| WordPress | XSS, SQLi, CSRF, escalada, upload, plugins | ✅ | Genéricos + Known Vulnerabilities (WP, enumeración de plugins con versión) | Detecta WP, REST users, xmlrpc y plugins+versión |
| Drupal | RCE, XSS, SQLi, bypass de acceso, upload, dependencias | 🟡 | Conocidos + A06 + Drupal | Detección básica |
| TYPO3 | RCE, XSS, SQLi, auth, autorización, exposición | 🟡 | Genéricos | Cobertura básica |

## Estado de los pendientes específicos de PHP

- ✅ Wrappers LFI: `php://filter` y `data://` cubiertos en `checkPHPWrappers`
  (`phar://` requiere subir un archivo .phar, fuera del alcance de caja negra).
- ✅ Deserialización PHP (`unserialize`): `checkPHPDeserialization` exige una firma real de error de
  deserialización en la respuesta, no un reflejo del payload.
- ✅ Exposición de `composer.json`/`vendor`: `checkSensitiveFiles` + `checkSupplyChainExposure`.
- ✅ Enumeración de plugins de WordPress con versión (`/wp-content/plugins/<plugin>/readme.txt` →
  `Stable tag`), accionable para cruzar con CVEs. Drupal: detección del CMS y superficies comunes.
  (Marcar un plugin como "vulnerable" automáticamente aún requeriría una base de CVE por versión.)
- ❌ Funciones peligrosas (`eval`, `assert`, `preg_replace /e`, `create_function`): son problemas de
  código fuente; no se detectan de forma fiable por caja negra (se cubren con SSTI/RCE/command injection
  cuando llegan a ser explotables vía HTTP).
