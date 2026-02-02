# 🔐 VersaSecurityTest v1.3.0 - Release Notes

**Fecha de lanzamiento**: 2 de febrero de 2026

## 🚀 Resumen de la Versión

VersaSecurityTest v1.3.0 es una actualización mayor que introduce la **Automatización Total de Releases** y una **Reforma Integral del Motor de Escaneado**. Esta versión eleva al scanner a un nivel profesional, con capacidades de detección avanzada y una experiencia de usuario optimizada mediante perfiles inteligentes.

## ✨ Nuevas Características Principales

### 🤖 Automatización CI/CD (GitHub Actions)

- **Despliegue Multiplataforma**: Generación automática de binarios para **Windows (amd64)**, **Linux (amd64)** y **macOS (amd64/arm64)**.
- **Workflows Automatizados**: Cada tag `v*` ahora dispara una release completa con artefactos optimizados y comprimidos.

### 🖥️ TUI: Progreso y Perfiles en Tiempo Real

- **Perfiles de Escaneo Dinámicos**: Selección visual entre perfiles **Básico, Estándar y Avanzado**, cada uno con configuraciones predefinidas de timeout y concurrencia.
- **Monitor de Progreso Avanzado**: Visualización interactiva de cada test individual, mostrando su estado ("pending", "running", "completed") y duración en tiempo real.
- **Navegación de Resultados**: Soporte para scroll completo en la pantalla de resultados, permitiendo analizar reportes extensos sin salir de la interfaz.
- **Spinners de Estado**: Nuevos indicadores visuales para estados intermedios como la generación de archivos de reporte.

### 🔍 Motor de Escaneado Profesional

- **Advanced XSS Test**: Sistema de detección mejorado que clasifica vulnerabilidades en **Reflected, Stored y DOM XSS**, analizando elementos peligrosos de forma granular.
- **Advanced Directory Traversal**: Lógica de análisis de rutas completamente rediseñada para una detección más precisa de fugas de datos.
- **File Upload Security**: Nuevo módulo dedicado a detectar formularios de carga de archivos y endpoints vulnerables.
- **Information Disclosure**: Scanner para descubrimiento de información sensible en headers (Server, X-Powered-By) y en el cuerpo de las respuestas.

## 🔧 Mejoras Técnicas

### 🏗️ Arquitectura y Configuración

- **Configuración Granular**: El archivo `config.json` ahora soporta categorías OWASP (Authentication, Authorization, Session Mgmt, etc.).
- **Unificación de Lógica**: CLI y TUI ahora comparten el mismo núcleo de ejecución `scanner.ExecuteScan`.
- **Auto-Save Inteligente**: Persistencia automática de la última URL y preferencias de protocolo.
- **Manejo de Tiempos**: Implementación de tickers internos para actualizaciones de UI más fluidas (200ms).

## 📦 Binarios Incluidos

Cada release ahora incluye automáticamente:

- `versaSecurityTest-v1.3.0-windows-amd64.zip`
- `versaSecurityTest-v1.3.0-linux-amd64.tar.gz`
- `versaSecurityTest-v1.3.0-macos-amd64.tar.gz`
- `versaSecurityTest-v1.3.0-macos-arm64.tar.gz`

## 🔗 Próximos Pasos (v1.4.0)

- Integración profunda con el top 10 de OWASP 2021.
- Reportes en formato PDF con gráficas de riesgo.
- Historial de escaneos persistente en base de datos local.

---

**🔐 VersaSecurityTest v1.3.0** - Potencia, precisión y automatización en un solo scanner.

**💡 ¡Prueba la nueva experiencia ejecutando simplemente `./versaSecurityTest` y seleccionando el perfil "Advanced"!**
