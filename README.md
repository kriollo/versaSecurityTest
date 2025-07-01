# 🔐 VersaSecurityTest

**VersaSecurityTest** es un scanner de seguridad web automático desarrollado en Go, diseñado para identificar vulnerabilidades comunes en aplicaciones web de manera rápida y eficiente.

![VersaSecurityTest Banner](https://img.shields.io/badge/VersaSecurityTest-v1.1.0-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![Status](https://img.shields.io/badge/Status-Stable-green.svg)

## ✨ Características

### 🎯 Tests de Seguridad Implementados
- **Conectividad Básica**: Verifica conectividad y respuesta del servidor objetivo
- **SQL Injection**: Detecta vulnerabilidades de inyección SQL mediante análisis de respuestas
- **Cross-Site Scripting (XSS)**: Identifica posibles vectores de ataque XSS
- **Headers de Seguridad**: Verifica la presencia de headers críticos de seguridad
- **Divulgación de Información**: Detecta exposición de información sensible del servidor
- **SSL/TLS Security**: Evaluación básica de configuración SSL/TLS
- **CSRF Protection**: Verificación de protecciones contra CSRF
- **Brute Force**: Tests básicos de fuerza bruta
- **File Upload**: Validación de controles de subida de archivos
- **Directory Traversal**: Detección de vulnerabilidades de path traversal

### 📊 Formatos de Salida
- **JSON**: Formato estructurado para integración con otras herramientas
- **Tabla ASCII**: Visualización clara y organizada en terminal
- **HTML**: Reporte profesional con diseño responsivo

### 🎮 Modos de Funcionamiento
- **CLI Mode**: Interfaz de línea de comandos directa
- **TUI Mode**: Interfaz de terminal moderna e interactiva

### ⚙️ Configuración Flexible
- Archivo de configuración JSON personalizable
- Opciones de línea de comandos
- Modo verbose para debugging detallado
- Configuración de timeouts y concurrencia

## 🚀 Instalación

### Prerrequisitos
- Go 1.21 o superior (para compilar desde código fuente)

### Compilación desde el código fuente

```bash
# Clonar el repositorio
git clone https://github.com/kriollo/versaSecurityTest.git
cd versaSecurityTest

# Descargar dependencias
go mod tidy

# Compilar el proyecto
go build -o versaSecurityTest.exe      # Windows
go build -o versaSecurityTest          # Linux/macOS
```

### Usar binarios precompilados
El proyecto incluye binarios precompilados en la carpeta `releases/`:
- Windows: `versaSecurityTest-v1.1.0-windows-amd64.exe`
- Linux: `versaSecurityTest-v1.1.0-linux-amd64`
- macOS Intel: `versaSecurityTest-v1.1.0-darwin-amd64`
- macOS ARM: `versaSecurityTest-v1.1.0-darwin-arm64`

## 🎮 Modos de Uso

### 1. 🎨 Modo TUI (Terminal User Interface)

Interfaz moderna e interactiva con navegación visual:

```bash
# Windows
.\versaSecurityTest.exe -tui

# Linux/macOS
./versaSecurityTest -tui
```

**Características del Modo TUI:**
- Selección visual de protocolo (HTTP/HTTPS)
- Ingreso de URL con validación
- Selección múltiple de tests de seguridad
- Configuración de formato de salida
- Progreso en tiempo real durante el escaneo
- Vista de resultados interactiva

**Controles TUI:**
- `↑↓←→`: Navegación entre opciones
- `Space`: Seleccionar/Deseleccionar
- `Enter`: Continuar/Confirmar
- `A`: Seleccionar todos los tests
- `N`: Deseleccionar todos los tests
- `V`: Activar/Desactivar modo verbose
- `S`: Saltar test actual (durante escaneo)
- `Q/Ctrl+C`: Salir de la aplicación

### 2. ⚡ Modo CLI Directo

Ejecución directa con parámetros (requiere URL):

```bash
# Escaneo básico
.\versaSecurityTest.exe -url https://ejemplo.com

# Con configuración personalizada
.\versaSecurityTest.exe -url https://ejemplo.com -format table -verbose
```

### 3. 🔄 Modo por Defecto

Sin parámetros (muestra ayuda):

```bash
.\versaSecurityTest.exe
```

## ⚙️ Opciones de Línea de Comandos

```bash
Usage of versaSecurityTest:
  -url string
        URL objetivo para escanear (requerido para modo CLI)
  -tui
        Activar modo Terminal User Interface
  -output string
        Archivo de salida para el reporte (opcional)
  -config string
        Archivo de configuración (default "config.json")
  -verbose
        Modo verbose para debugging
  -format string
        Formato de salida (json, table, html) (default "json")
  -concurrent int
        Número de requests concurrentes (default 10)
  -timeout duration
        Timeout por request (default 30s)
```

## 💡 Ejemplos de Uso

```bash
# Modo TUI (recomendado)
.\versaSecurityTest.exe -tui

# Escaneo básico con salida JSON
.\versaSecurityTest.exe -url https://httpbin.org/get

# Escaneo con formato de tabla
.\versaSecurityTest.exe -url https://ejemplo.com -format table

# Generar reporte HTML
.\versaSecurityTest.exe -url https://ejemplo.com -format html -output reporte.html

# Modo verbose con configuración personalizada
.\versaSecurityTest.exe -url https://ejemplo.com -verbose -concurrent 5 -timeout 45s

# Usando archivo de configuración personalizado
.\versaSecurityTest.exe -url https://ejemplo.com -config mi-config.json
```

## ⚙️ Configuración

### Archivo de Configuración (config.json)

```json
{
  "concurrent": 5,
  "timeout": 30000000000,
  "user_agent": "VersaSecurityTest/1.1 (Security Scanner)",
  "headers": {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive"
  },
  "tests": {
    "basic": true,
    "sql_injection": true,
    "xss": true,
    "brute_force": false,
    "csrf": false,
    "directory_traversal": false,
    "file_upload": false,
    "http_headers": true,
    "ssl": false,
    "information_disclosure": true
  },
  "verbose": false
}
```

### Configuración de Tests

| Test | Descripción | Estado por Defecto |
|------|-------------|-------------------|
| `basic` | Conectividad y respuesta básica | ✅ Habilitado |
| `sql_injection` | Detecta vulnerabilidades de inyección SQL | ✅ Habilitado |
| `xss` | Identifica vectores de ataque XSS | ✅ Habilitado |
| `http_headers` | Verifica headers de seguridad | ✅ Habilitado |
| `information_disclosure` | Divulgación de información | ✅ Habilitado |
| `brute_force` | Tests de fuerza bruta | ❌ Deshabilitado |
| `csrf` | Vulnerabilidades CSRF | ❌ Deshabilitado |
| `directory_traversal` | Path traversal | ❌ Deshabilitado |
| `file_upload` | Validación de subida de archivos | ❌ Deshabilitado |
| `ssl` | Configuración SSL/TLS | ❌ Deshabilitado |

## 📊 Interpretación de Resultados

### Puntuación de Seguridad

El scanner asigna una puntuación de 0 a 10 basada en:
- **Número de tests pasados vs fallidos**
- **Severidad de las vulnerabilidades encontradas**
- **Factores de penalización por tipo de problema**

### Niveles de Riesgo

| Puntuación | Nivel de Riesgo | Descripción |
|------------|-----------------|-------------|
| 8.0 - 10.0 | 🟢 **Bajo** | Configuración de seguridad sólida |
| 6.0 - 7.9 | 🟡 **Medio** | Algunos problemas que requieren atención |
| 4.0 - 5.9 | 🟠 **Alto** | Vulnerabilidades significativas presentes |
| 0.0 - 3.9 | 🔴 **Crítico** | Problemas graves de seguridad |

### Tipos de Evidencia

- **SQL Injection**: Respuestas del servidor que indican inyección SQL exitosa
- **Missing Security Header**: Headers de seguridad faltantes
- **Information Disclosure**: Exposición de información del servidor
- **HTTP Error**: Códigos de estado que indican problemas
- **XSS**: Comportamiento anómalo con payloads XSS

## 📝 Ejemplo de Salida

### Formato JSON
```json
{
  "url": "https://ejemplo.com",
  "scan_date": "2024-01-15T10:30:00Z",
  "duration": 5234000000,
  "tests_executed": 5,
  "tests_passed": 3,
  "tests_failed": 2,
  "security_score": {
    "value": 6.5,
    "risk": "Medium"
  },
  "test_results": [
    {
      "test_name": "Basic Connectivity",
      "status": "Passed",
      "description": "Connection successful",
      "severity": "None"
    },
    {
      "test_name": "SQL Injection",
      "status": "Failed",
      "description": "Potential SQL injection vulnerability detected",
      "severity": "High"
    },
    {
      "test_name": "Security Headers Check",
      "status": "Failed",
      "description": "Missing critical security headers",
      "severity": "Medium"
    }
  ]
}
```

### Formato Tabla
```
┌─────────────────────────────────────────────────────────────────┐
│                    REPORTE DE SEGURIDAD WEB                     │
├─────────────────────────────────────────────────────────────────┤
│ URL Objetivo: https://ejemplo.com                               │
│ Fecha: 2024-01-15 10:30:00                                      │
│ Duración: 5.234s                                                │
├─────────────────────────────────────────────────────────────────┤
│ Tests Ejecutados: 5 | Pasados: 3 | Fallidos: 2                 │
│ Puntuación de Seguridad: 6.5/10 (Medium)                       │
└─────────────────────────────────────────────────────────────────┘
```

## 🏗️ Arquitectura del Proyecto

```
versaSecurityTest/
├── main.go                          # Punto de entrada principal
├── config.json                      # Configuración por defecto
├── README.md                        # Documentación
├── go.mod                          # Definición del módulo Go
├── go.sum                          # Checksums de dependencias
├── internal/
│   ├── cli/
│   │   └── types.go                # Tipos para CLI
│   ├── config/
│   │   └── config.go               # Manejo de configuración
│   ├── scanner/
│   │   ├── scanner.go              # Lógica principal del scanner
│   │   └── tests/                  # Tests de seguridad implementados
│   ├── report/
│   │   └── report.go               # Generación de reportes
│   └── tui/
│       ├── ui.go                   # Interfaz TUI
│       ├── handlers.go             # Manejo de eventos TUI
│       ├── render.go               # Renderizado de pantallas
│       └── scan.go                 # Lógica de escaneo TUI
└── releases/                       # Binarios precompilados
```

## ️ Desarrollo

### Agregar Nuevos Tests

Para implementar un nuevo test de seguridad:

1. **Crear el test** en `internal/scanner/tests/`
2. **Registrar el test** en `scanner.go`
3. **Agregar configuración** en `config.go`

### Ejecutar Tests de Desarrollo

```bash
# Ejecutar tests unitarios
go test ./...

# Test de integración básico
go run main.go -url https://httpbin.org/get -verbose
```

## 🤝 Contribución

### Guías de Contribución

1. **Fork** el repositorio
2. **Crear** una rama para tu feature (`git checkout -b feature/amazing-feature`)
3. **Commit** tus cambios (`git commit -m 'Add amazing feature'`)
4. **Push** a la rama (`git push origin feature/amazing-feature`)
5. **Abrir** un Pull Request

### Estándares de Código

- Seguir las convenciones de Go (`gofmt`, `golint`)
- Incluir tests unitarios para nuevas funcionalidades
- Documentar funciones públicas
- Mantener compatibilidad hacia atrás

### Reportar Bugs

Usa las [GitHub Issues](https://github.com/kriollo/versaSecurityTest/issues) para reportar bugs, incluyendo:
- Descripción detallada del problema
- Pasos para reproducir
- Salida esperada vs actual
- Información del sistema (OS, versión de Go)

## ⚠️ Consideraciones Legales y Éticas

### ⚖️ Uso Responsable

**IMPORTANTE**: Este scanner está diseñado exclusivamente para:
- ✅ Testing de seguridad en sistemas propios
- ✅ Auditorías autorizadas con permiso explícito
- ✅ Entornos de desarrollo y testing
- ✅ Investigación educativa en laboratorios controlados

### 🚫 Uso Prohibido

**NUNCA uses esta herramienta para**:
- ❌ Atacar sistemas sin autorización
- ❌ Actividades ilegales o maliciosas
- ❌ Violar términos de servicio
- ❌ Causar daño a infraestructuras

### 📋 Disclaimers

- Los usuarios son completamente responsables del uso de esta herramienta
- Los desarrolladores no se hacen responsables por mal uso
- Siempre obtén autorización explícita antes de escanear sistemas
- Cumple con las leyes locales e internacionales

## 📜 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para detalles.

```
MIT License

Copyright (c) 2025 versaSecurityTest

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

## 📞 Contacto y Soporte

- **GitHub Issues**: [Reportar problemas](https://github.com/kriollo/versaSecurityTest/issues)
- **Documentación**: [Wiki del proyecto](https://github.com/kriollo/versaSecurityTest/wiki)
- **Discusiones**: [GitHub Discussions](https://github.com/kriollo/versaSecurityTest/discussions)

## 🎯 Roadmap

### ✅ Versión 1.1.0 (Actual)
- [x] **Interfaz TUI moderna** con navegación interactiva
- [x] **Múltiples modos de funcionamiento** (CLI, TUI)
- [x] **Tests de seguridad centralizados** con lógica unificada
- [x] **Generación de reportes** en múltiples formatos
- [x] **Funcionalidad de skip** durante ejecución de tests
- [x] **Cálculo correcto de security score**

### Versión 1.2.0 (Planificada)
- [ ] Tests avanzados de SQL Injection con múltiples payloads
- [ ] Detección mejorada de vulnerabilidades CSRF
- [ ] Scanner de headers de seguridad más completo
- [ ] Tests de SSL/TLS más detallados
- [ ] Mejoras en la interfaz TUI

### Versión 2.0.0 (Futuro)
- [ ] Interfaz web opcional
- [ ] Base de datos de resultados históricos
- [ ] API REST para integración
- [ ] Sistema de plugins
- [ ] Reportes programados

## 🏆 Reconocimientos

- Inspirado en herramientas como OWASP ZAP y Nikto
- Desarrollado con las mejores prácticas de Go
- Agradecimientos a la comunidad de seguridad web

---

<div align="center">

**🔐 VersaSecurityTest v1.1.0 - Scanner de Seguridad Web Unificado**

**✨ Versión 1.1**: CLI y TUI unificados, lógica centralizada, reportes precisos

[⭐ Dale una estrella si te gusta el proyecto](https://github.com/kriollo/versaSecurityTest)

</div>
