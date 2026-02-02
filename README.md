# 🔐 VersaSecurityTest

**VersaSecurityTest** es un scanner de seguridad web automático desarrollado en Go, diseñado para identificar vulnerabilidades comunes en aplicaciones web de manera rápida y eficiente.

![VersaSecurityTest Banner](https://img.shields.io/badge/VersaSecurityTest-v1.3.0-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![Status](https://img.shields.io/badge/Status-Stable-green.svg)

## ✨ Características

### 🎯 Tests de Seguridad Implementados

- **Conectividad Básica**: Verifica conectividad y respuesta del servidor objetivo.
- **Recopilación de Información**: Identifica tecnologías y endpoints.
- **Revisión de Configuración**: Analiza configuraciones de seguridad del servidor.
- **Validación de Entradas**: Evalúa la sanitización de datos de entrada.
- **Pruebas de Autenticación**: Verifica mecanismos de identidad y control de acceso.
- **Gestión de Sesiones**: Analiza la seguridad de los tokens y cookies de sesión.
- **Pruebas de Autorización**: Comprueba que los usuarios solo puedan acceder a los recursos permitidos.
- **Inyección SQL**: Detecta vulnerabilidades de inyección SQL.
- **Cross-Site Scripting (XSS)**: Identifica posibles vectores de ataque XSS.
- **Headers de Seguridad**: Verifica la presencia de headers críticos de seguridad.
- **Divulgación de Información Sensible**: Detecta exposición de datos sensibles.
- **Seguridad SSL/TLS**: Evaluación de la configuración SSL/TLS.
- **Protección CSRF**: Verificación de defensas contra Cross-Site Request Forgery.
- **Fuerza Bruta**: Tests básicos de fuerza bruta sobre formularios de login.
- **Subida de Archivos (File Upload)**: Valida controles en la subida de archivos.
- **Directory Traversal**: Detección de vulnerabilidades de path traversal.
- **Pruebas de API de Cliente**: Revisa la seguridad de las APIs expuestas al cliente.
- **Pruebas Adicionales**: Incluye verificaciones de seguridad variadas.

### 📊 Formatos de Salida

- **JSON**: Formato estructurado para integración con otras herramientas
- **Tabla ASCII**: Visualización clara y organizada en terminal
- **HTML**: Reporte profesional con diseño responsivo

### 🎮 Modos de Funcionamiento

- **TUI Mode**: Interfaz de terminal moderna e interactiva (modo por defecto)
- **CLI Mode**: Interfaz de línea de comandos directa

### 📈 Perfiles de Escaneo

- **Básico**: Escaneo rápido con tests fundamentales (5s timeout, 3 concurrent)
- **Estándar**: Escaneo balanceado con tests principales (30s timeout, 5 concurrent)
- **Avanzado**: Escaneo completo con todos los tests (60s timeout, 10 concurrent)

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

## 🎮 Modos de Uso

### 1. 🎨 Modo TUI (Terminal User Interface) - POR DEFECTO

Interfaz moderna e interactiva con navegación visual:

```bash
# Windows - Modo por defecto (sin parámetros)
.\versaSecurityTest.exe

# Linux/macOS - Modo por defecto (sin parámetros)
./versaSecurityTest
```

**Características del Modo TUI:**

- Selección visual de protocolo (HTTP/HTTPS)
- Ingreso de URL con validación
- **Selección de perfil de escaneo** (Básico/Estándar/Avanzado)
- Selección múltiple de tests de seguridad
- Configuración de formato de salida
- Progreso en tiempo real durante el escaneo
- Vista de resultados interactiva con scroll
- Guardado silencioso de reportes (sin diálogos modales)

**Controles TUI:**

- `↑↓←→`: Navegación entre opciones
- `Space`: Seleccionar/Deseleccionar
- `Enter`: Continuar/Confirmar
- `A`: Seleccionar todos los tests
- `N`: Deseleccionar todos los tests
- `R`: Seleccionar solo tests recomendados
- `V`: Activar/Desactivar modo verbose
- `S`: Guardar reporte (en pantalla de resultados)
- `Backspace`: Volver al inicio (reinicio completo)
- `Q/Ctrl+C`: Salir de la aplicación

### 2. ⚡ Modo CLI Directo

Ejecución directa con parámetros (requiere -url o -cli):

```bash
# Escaneo básico con CLI
.\versaSecurityTest.exe -url https://ejemplo.com

# Forzar modo CLI explícitamente
.\versaSecurityTest.exe -cli -url https://ejemplo.com -format table -verbose
```

### 3. 🔄 Modo por Defecto (TUI)

Sin parámetros (inicia TUI):

```bash
.\versaSecurityTest.exe
```

## ⚙️ Opciones de Línea de Comandos

```bash
Usage of versaSecurityTest:
  -url string
        URL objetivo para escanear (requerido para modo CLI)
  -cli
        Forzar modo CLI (línea de comandos)
  -output string
        Archivo de salida para el reporte (opcional)
  -config string
        Archivo de configuración (default "config.json")
  -verbose
        Modo verbose para debugging
  -format string
        Formato de salida (json, table, html) (default "json")
  -concurrent int
        Número de requests concurrentes (default 5)
  -timeout duration
        Timeout por request (default 30s)
  -profile string
        Perfil de escaneo (basic, standard, advanced) (default "standard")
```

## 💡 Ejemplos de Uso

```bash
# Modo TUI (por defecto - recomendado)
.\versaSecurityTest.exe

# Escaneo básico CLI con salida JSON
.\versaSecurityTest.exe -url https://httpbin.org/get

# Escaneo CLI con formato de tabla
.\versaSecurityTest.exe -url https://ejemplo.com -format table

# Generar reporte HTML
.\versaSecurityTest.exe -url https://ejemplo.com -format html -output reporte.html

# Modo verbose con configuración personalizada
.\versaSecurityTest.exe -url https://ejemplo.com -verbose -concurrent 5 -timeout 45s

# Usando perfil de escaneo específico
.\versaSecurityTest.exe -url https://ejemplo.com -profile advanced

# Usando archivo de configuración personalizado
.\versaSecurityTest.exe -url https://ejemplo.com -config mi-config.json
```

## ⚙️ Configuración

### Archivo de Configuración (config.json)

```json
{
  "concurrent": 5,
  "timeout": 30000000000,
  "user_agent": "VersaSecurityTest/1.2 (Security Scanner)",
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
    "information_disclosure": true,
    "use_advanced_tests": false
  },
  "scan_profiles": {
    "basic": {
      "timeout": 5000000000,
      "concurrent": 3,
      "enabled_tests": {
        "basic": true,
        "sql_injection": false,
        "xss": false,
        "brute_force": false,
        "csrf": false,
        "directory_traversal": false,
        "file_upload": false,
        "http_headers": true,
        "ssl": false,
        "information_disclosure": false,
        "use_advanced_tests": false
      }
    },
    "standard": {
      "timeout": 30000000000,
      "concurrent": 5,
      "enabled_tests": {
        "basic": true,
        "sql_injection": true,
        "xss": true,
        "brute_force": false,
        "csrf": false,
        "directory_traversal": false,
        "file_upload": false,
        "http_headers": true,
        "ssl": false,
        "information_disclosure": true,
        "use_advanced_tests": false
      }
    },
    "advanced": {
      "timeout": 60000000000,
      "concurrent": 10,
      "enabled_tests": {
        "basic": true,
        "sql_injection": true,
        "xss": true,
        "brute_force": true,
        "csrf": true,
        "directory_traversal": true,
        "file_upload": true,
        "http_headers": true,
        "ssl": true,
        "information_disclosure": true,
        "use_advanced_tests": true
      }
    }
  },
  "verbose": false
}
```

### Configuración de Tests

| Test                     | Descripción                               | Básico | Estándar | Avanzado |
| ------------------------ | ----------------------------------------- | ------ | -------- | -------- |
| `basic`                  | Conectividad y respuesta básica           | ✅     | ✅       | ✅       |
| `http_headers`           | Verifica headers de seguridad             | ✅     | ✅       | ✅       |
| `sql_injection`          | Detecta vulnerabilidades de inyección SQL | ❌     | ✅       | ✅       |
| `xss`                    | Identifica vectores de ataque XSS         | ❌     | ✅       | ✅       |
| `information_disclosure` | Divulgación de información                | ❌     | ✅       | ✅       |
| `brute_force`            | Tests de fuerza bruta                     | ❌     | ❌       | ✅       |
| `csrf`                   | Vulnerabilidades CSRF                     | ❌     | ❌       | ✅       |
| `directory_traversal`    | Path traversal                            | ❌     | ❌       | ✅       |
| `file_upload`            | Validación de subida de archivos          | ❌     | ❌       | ✅       |
| `ssl`                    | Configuración SSL/TLS                     | ❌     | ❌       | ✅       |

### Perfiles de Escaneo

| Perfil       | Timeout | Concurrencia | Tests Habilitados | Descripción                         |
| ------------ | ------- | ------------ | ----------------- | ----------------------------------- |
| **Básico**   | 5s      | 3            | 2 tests           | Escaneo rápido y básico             |
| **Estándar** | 30s     | 5            | 5 tests           | Balance entre velocidad y cobertura |
| **Avanzado** | 60s     | 10           | 10 tests          | Escaneo completo y exhaustivo       |

## 📊 Interpretación de Resultados

### Puntuación de Seguridad

El scanner asigna una puntuación de 0 a 10 basada en:

- **Número de tests pasados vs fallidos**
- **Severidad de las vulnerabilidades encontradas**
- **Factores de penalización por tipo de problema**

### Niveles de Riesgo

| Puntuación | Nivel de Riesgo | Descripción                               |
| ---------- | --------------- | ----------------------------------------- |
| 8.0 - 10.0 | 🟢 **Bajo**     | Configuración de seguridad sólida         |
| 6.0 - 7.9  | 🟡 **Medio**    | Algunos problemas que requieren atención  |
| 4.0 - 5.9  | 🟠 **Alto**     | Vulnerabilidades significativas presentes |
| 0.0 - 3.9  | 🔴 **Crítico**  | Problemas graves de seguridad             |

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
└── releases/                       # Notas de lanzamiento y checksums
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

### ✅ Versión 1.3.0 (Actual)

- [x] **Unificación completa CLI/TUI** con lógica centralizada de escaneado
- [x] **Perfiles de escaneo** (Básico, Estándar, Avanzado) con configuración automática
- [x] **TUI como modo por defecto** con interfaz mejorada
- [x] **Pantalla de selección de perfiles** en el flujo TUI
- [x] **Scroll mejorado y navegación** en pantalla de resultados
- [x] **Eliminación de diálogos modales** para interfaz más limpia
- [x] **Timeout y cancelación unificados** entre CLI y TUI
- [x] **Corrección de panics de renderizado** y estabilidad general
- [x] **Guardado silencioso de reportes** sin confirmaciones modales

### Versión 1.3.0 (Planificada)

- [ ] Tests avanzados de SQL Injection con múltiples payloads
- [ ] Detección mejorada de vulnerabilidades CSRF
- [ ] Scanner de headers de seguridad más completo
- [ ] Tests de SSL/TLS más detallados
- [ ] Sistema de configuración por URL/dominio

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

**🔐 VersaSecurityTest v1.3.0 - Scanner de Seguridad Web Unificado**

**✨ Versión 1.2**: Perfiles de escaneo, TUI por defecto, lógica unificada CLI/TUI, interfaz sin modales

[⭐ Dale una estrella si te gusta el proyecto](https://github.com/kriollo/versaSecurityTest)

</div>
