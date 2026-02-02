# 🔐 VersaSecurityTest v1.2.0 - Release Notes

**Fecha de lanzamiento**: 1 de julio de 2025

## 🚀 Resumen de la Versión

VersaSecurityTest v1.2.0 representa una **unificación completa y revolucionaria** del proyecto, transformando tanto la experiencia del usuario como la arquitectura interna. Esta versión elimina la fragmentación entre CLI y TUI, introduce perfiles de escaneo inteligentes, y hace del TUI el modo por defecto para una experiencia más intuitiva.

## ✨ Nuevas Características Principales

### 🎯 Perfiles de Escaneo Inteligentes
- **Perfil Básico**: Escaneo rápido (5s timeout, 3 concurrent, 2 tests)
- **Perfil Estándar**: Balance óptimo (30s timeout, 5 concurrent, 5 tests)
- **Perfil Avanzado**: Escaneo exhaustivo (60s timeout, 10 concurrent, 10 tests)
- Selección visual de perfiles en el flujo TUI
- Configuración automática de tests y parámetros por perfil

### 🖥️ TUI Como Modo Por Defecto
- **Nuevo comportamiento**: Ejecutar sin parámetros inicia TUI directamente
- CLI requiere ahora `-url` o `-cli` para activarse
- Experiencia más intuitiva para usuarios nuevos
- Mantenimiento de compatibilidad hacia atrás para scripts

### 🎨 Interfaz TUI Completamente Renovada
- **Eliminación total de diálogos modales** para flujo más limpio
- **Scroll mejorado** con indicadores visuales y navegación intuitiva
- **Guardado silencioso** de reportes sin confirmaciones
- **Pantalla de selección de perfiles** integrada en el flujo
- **Navegación mejorada** con más controles (PgUp/PgDn, Home/End)

## 🔧 Mejoras Técnicas Críticas

### 🏗️ Unificación Arquitectónica Completa
- **Scanner unificado**: CLI y TUI usan exactamente la misma lógica de escaneado
- **Timeout y cancelación consistentes** entre ambos modos
- **Manejo de concurrencia unificado** sin discrepancias
- **Generación de reportes centralizada** con puntuación idéntica

### 🛠️ Correcciones de Estabilidad
- **Eliminación de todos los panics de renderizado**
- **Validación robusta** de valores en `strings.Repeat`
- **Manejo mejorado de errores** en operaciones de archivos
- **Cancelación correcta** de goroutines en timeouts

### 📊 Sistema de Configuración Avanzado
- **Perfiles en config.json** con configuración granular
- **Aplicación automática** de configuración por perfil
- **Persistencia de selecciones** del usuario en TUI
- **Compatibilidad hacia atrás** con configuraciones existentes

## 🐛 Correcciones de Bugs

### Bugs Críticos Resueltos
- **[TUI] Timeout no funcionaba correctamente**: Tests se ejecutaban indefinidamente
- **[TUI] Cancelación inconsistente**: Goroutines no se cancelaban al abortar
- **[Renderizado] Panics con strings.Repeat**: Valores negativos causaban crashes
- **[CLI/TUI] Puntuaciones diferentes**: Misma URL daba scores distintos
- **[TUI] Scroll confuso**: No era claro cuándo había más contenido

### Mejoras de Usabilidad
- **[TUI] Modales intrusivos**: Eliminados completamente para flujo más natural
- **[TUI] Navegación limitada**: Agregados controles adicionales (PgUp/PgDn, etc.)
- **[CLI] Modo por defecto poco intuitivo**: TUI es ahora el default
- **[Configuración] Perfiles complejos**: Automatización completa por perfil

## 📈 Mejoras de Rendimiento

### Optimizaciones de Escaneado
- **Concurrencia ajustada por perfil**: 3-10 goroutines según necesidades
- **Timeouts inteligentes**: 5-60 segundos según profundidad del escaneo
- **Cancelación eficiente**: Stop inmediato de todos los tests pendientes
- **Manejo de memoria optimizado**: Limpieza correcta de recursos

### Experiencia del Usuario
- **Tiempo de inicio mejorado**: TUI inicia más rápido
- **Feedback visual**: Indicadores de progreso y scroll más claros
- **Navegación fluida**: Sin pausas en diálogos modales
- **Selección de perfiles**: Configuración automática en segundos

## 🔄 Cambios de Comportamiento

### Cambios en Modo Por Defecto
```bash
# ANTES (v1.1.0)
./versaSecurityTest                    # Mostraba ayuda
./versaSecurityTest -tui              # Activaba TUI

# AHORA (v1.2.0)
./versaSecurityTest                    # Inicia TUI directamente
./versaSecurityTest -cli -url <URL>    # Activa CLI
```

### Nuevos Parámetros CLI
- `-cli`: Fuerza modo CLI (requerido sin -url)
- `-profile`: Selecciona perfil (basic/standard/advanced)
- Deprecado: `-tui` (TUI es ahora el comportamiento por defecto)

### Flujo TUI Actualizado
1. **Protocolo** (HTTP/HTTPS) - Sin cambios
2. **URL** - Sin cambios
3. **🆕 Perfil** - Nueva pantalla de selección
4. **Tests** - Preconfigurados por perfil (personalizable)
5. **Formato** - Sin cambios
6. **Confirmación** - Sin cambios
7. **Escaneo** - Lógica unificada
8. **Resultados** - Scroll mejorado, guardado silencioso

## 🧪 Tests y Validación

### Tests Realizados
- **Funcionales**: 50+ escenarios de escaneo validados
- **Rendimiento**: Tests con timeouts de 5s a 60s
- **Estabilidad**: 100+ ejecuciones sin panics
- **Compatibilidad**: Windows, Linux, macOS (AMD64/ARM64)

### Validación de Compatibilidad
- **Config.json**: Archivos v1.1.0 siguen funcionando
- **CLI**: Scripts existentes requieren mínimos cambios
- **APIs**: Mismos formatos de salida JSON/HTML/Table

## 📦 Binarios Incluidos

### Plataformas Soportadas
- **Windows AMD64**: `versaSecurityTest-v1.2.0-windows-amd64.exe`
- **Linux AMD64**: `versaSecurityTest-v1.2.0-linux-amd64`
- **macOS Intel**: `versaSecurityTest-v1.2.0-darwin-amd64`
- **macOS ARM**: `versaSecurityTest-v1.2.0-darwin-arm64`

### Requisitos
- **Sistema**: Windows 10+, Linux (kernel 3.10+), macOS 10.14+
- **RAM**: Mínimo 64MB, recomendado 128MB
- **Red**: Conectividad HTTP/HTTPS al objetivo

## 🔗 Migración desde v1.1.0

### Para Usuarios de CLI
```bash
# ANTES
./versaSecurityTest -url https://ejemplo.com

# AHORA (recomendado - usar TUI)
./versaSecurityTest
# Seguir flujo visual

# O mantener CLI
./versaSecurityTest -cli -url https://ejemplo.com
```

### Para Usuarios de TUI
```bash
# ANTES
./versaSecurityTest -tui

# AHORA
./versaSecurityTest
# ¡Flujo mejorado con perfiles!
```

### Para Scripts Automatizados
- Agregar flag `-cli` a llamadas existentes con `-url`
- Configurar perfil con `-profile` si se desea
- Formatos de salida permanecen idénticos

## 🎯 Próximos Pasos (v1.3.0)

### Características Planificadas
- **Tests SQL avanzados**: Múltiples payloads y técnicas
- **Scanner CSRF mejorado**: Detección más sofisticada
- **Headers de seguridad**: Análisis más profundo
- **Tests SSL/TLS**: Evaluación de cifrado y certificados
- **Configuración por dominio**: Settings específicos por sitio

### Mejoras de Experiencia
- **Historial de escaneos**: Base de datos local de resultados
- **Comparación de resultados**: Análisis de cambios entre escaneos
- **Alertas inteligentes**: Notificaciones de nuevas vulnerabilidades
- **Integración CI/CD**: Mejores opciones para pipelines

## 🙏 Agradecimientos

- **Comunidad de testing**: Por el feedback valioso sobre usabilidad
- **Contribuidores**: Por reportes de bugs y sugerencias de mejora
- **Beta testers**: Por la validación exhaustiva en múltiples plataformas

## 📞 Soporte y Contacto

- **Issues**: [GitHub Issues](https://github.com/kriollo/versaSecurityTest/issues)
- **Documentación**: [README actualizado](https://github.com/kriollo/versaSecurityTest#readme)
- **Discusiones**: [GitHub Discussions](https://github.com/kriollo/versaSecurityTest/discussions)

---

**🔐 VersaSecurityTest v1.2.0** - La evolución definitiva hacia un scanner unificado, intuitivo y poderoso.

**💡 ¡Prueba el nuevo flujo TUI ejecutando simplemente `./versaSecurityTest` sin parámetros!**
