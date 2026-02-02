# 🔐 VersaSecurityTest v2.0.0 - Release Notes

**Fecha de lanzamiento**: 2 de febrero de 2026

## 🚀 Resumen de la Versión

VersaSecurityTest v2.0.0 es el salto más importante en la historia del proyecto. Hemos transformado el scanner de una herramienta de auditoría básica a una suite de seguridad avanzada totalmente alineada con los estándares **OWASP Top 10 2021**. Esta versión introduce capacidades de escaneo de red, detección profunda de componentes vulnerables y una experiencia de usuario (TUI) profesional y fluida.

## ✨ Nuevas Características Principales

### 🛡️ Integración Profunda OWASP Top 10 2021

- **A01: Broken Access Control**: Detección mejorada de endpoints administrativos expuestos y fallos en IDOR.
- **A06: Vulnerable and Outdated Components**: Nuevo motor de "fingerprinting" que detecta versiones de WordPress, Drupal, Apache y librerías desactualizadas a través de banners y rutas sensibles.
- **A08: Software and Data Integrity Failures**: Scanner de serialización insegura en Cookies (PHP/Java) y detección de descargas sin firma de integridad.
- **A10: SSRF Avanzado**: Payloads de evasión para saltar filtros básicos utilizando IPs en octal, decimal y bypasses de IPv6.

### 🌐 Network Port Scanning (NETW)

- **Escáner Concurrente**: Nuevo módulo `NETW-01` que identifica puertos abiertos y servicios expuestos (SSH, FTP, DBs, Paneles) utilizando la potencia de las goroutines.
- **Alertas de Seguridad**: Identificación automática de protocolos inseguros (Telnet, FTP, SMB) marcándolos como riesgos de seguridad.

### 🎮 TUI Pro: Navegación y Control Granular

- **Navegación Fluida**:
  - `Backspace / B`: Vuelve a la selección de tests para ajustar el escaneo actual sin reiniciar todo el proceso.
  - `P`: Regresa a la selección de perfiles.
  - `Enter`: Reintenta el escaneo actual instantáneamente.
  - `Ctrl+R`: Realiza un reinicio completo del scanner.
- **Selección de Tests Granular**: Ahora puedes activar o desactivar módulos individuales de OWASP y Red directamente desde la interfaz.

## 🔧 Mejoras Técnicas

- **Persistencia Inteligente**: Mejoras en el sistema de guardado de reportes para evitar colisiones.
- **Motor de Escaneo Optimizado**: Reducción del tiempo de escaneo mediante concurrencia ajustada por perfil.
- **Detección de 429 (Rate Limit)**: El scanner ahora identifica si está siendo bloqueado y ajusta los reportes para evitar falsos negativos.

## 📦 Binarios

Los binarios actualizados para v2.0.0 están disponibles a través de nuestro pipeline de CI/CD para:

- Windows (amd64)
- Linux (amd64)
- macOS (Intel & Silicon)

---

**🔐 VersaSecurityTest v2.0.0** - Seguridad profesional, abierta y potente.

**💡 ¡Prueba la nueva experiencia ejecutando `./versaSecurityTest` y selecciona el perfil "Advanced" para activar todos los nuevos módulos OWASP!**
