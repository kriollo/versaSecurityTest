# 🔐 VersaSecurityTest

**VersaSecurityTest** es un scanner de seguridad web automático desarrollado en Go, diseñado para identificar vulnerabilidades comunes en aplicaciones web de manera rápida y eficiente.

![VersaSecurityTest Banner](https://img.shields.io/badge/VersaSecurityTest-v1.0.0-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## ✨ Características

### 🎯 Tests de Seguridad Implementados
- **SQL Injection**: Detecta vulnerabilidades de inyección SQL mediante análisis de respuestas
- **Cross-Site Scripting (XSS)**: Identifica posibles vectores de ataque XSS
- **Headers de Seguridad**: Verifica la presencia de headers críticos de seguridad
- **Divulgación de Información**: Detecta exposición de información sensible del servidor
- **Conectividad Básica**: Pruebas fundamentales de conectividad y configuración

### 📊 Formatos de Salida
- **JSON**: Formato estructurado para integración con otras herramientas
- **Tabla ASCII**: Visualización clara y organizada en terminal
- **HTML**: Reporte profesional con diseño responsivo

### ⚙️ Configuración Flexible
- Archivo de configuración JSON personalizable
- Opciones de línea de comandos
- Modo verbose para debugging detallado
- Configuración de timeouts y concurrencia

## 🚀 Instalación

### Prerrequisitos
- Go 1.21 o superior
- Git (para clonar el repositorio)

### Compilación desde el código fuente

```bash
# Clonar el repositorio
git clone https://github.com/tuusuario/versaSecurityTest.git
cd versaSecurityTest

# Descargar dependencias
go mod tidy

# Compilar el proyecto
go build -o versaSecurityTest.exe

# En Linux/macOS
go build -o versaSecurityTest
```

### Descargas Precompiladas
Descarga los binarios precompilados desde la sección [Releases](https://github.com/tuusuario/versaSecurityTest/releases).

## 🎮 Uso Básico

### Comando Básico
```bash
# Windows
.\versaSecurityTest.exe -url https://ejemplo.com

# Linux/macOS
./versaSecurityTest -url https://ejemplo.com
```

### Opciones de Línea de Comandos

```bash
Usage of versaSecurityTest:
  -url string
        URL objetivo para escanear (requerido)
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

### Ejemplos de Uso

```bash
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
  "user_agent": "VersaSecurityTest/1.0 (Security Scanner)",
  "headers": {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive"
  },
  "tests": {
    "sql_injection": true,
    "xss": true,
    "brute_force": false,
    "csrf": false,
    "directory_traversal": false,
    "file_upload": false,
    "http_headers": true,
    "ssl": false,
    "ddos": false,
    "path_traversal": false,
    "authentication": false,
    "information_disclosure": false
  },
  "verbose": false
}
```

### Configuración de Tests

| Test | Descripción | Estado |
|------|-------------|--------|
| `sql_injection` | Detecta vulnerabilidades de inyección SQL | ✅ Implementado |
| `xss` | Identifica vectores de ataque XSS | ✅ Implementado |
| `http_headers` | Verifica headers de seguridad | ✅ Implementado |
| `brute_force` | Tests de fuerza bruta | 🚧 En desarrollo |
| `csrf` | Vulnerabilidades CSRF | 🚧 En desarrollo |
| `authentication` | Problemas de autenticación | 🚧 En desarrollo |
| `information_disclosure` | Divulgación de información | 🚧 En desarrollo |

## 📊 Interpretación de Resultados

### Puntuación de Seguridad

El scanner asigna una puntuación de 0 a 10 basada en:
- **Número de tests pasados vs fallidos**
- **Severidad de las vulnerabilidades encontradas**
- **Penalizaciones por tipo de problema**

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
  "scan_date": "2025-06-29T19:53:28Z",
  "duration": 746122400,
  "tests_executed": 3,
  "tests_passed": 2,
  "tests_failed": 1,
  "security_score": {
    "value": 5.7,
    "risk": "Alto"
  },
  "test_results": [
    {
      "test_name": "SQL Injection",
      "status": "Passed",
      "description": "No se detectaron vulnerabilidades evidentes",
      "severity": "None"
    }
  ],
  "recommendations": [
    "Implementar sanitización de entrada y usar consultas preparadas"
  ]
}
```

### Formato Tabla
```
┌─────────────────────────────────────────────────────────────────┐
│                    REPORTE DE SEGURIDAD WEB                     │
├─────────────────────────────────────────────────────────────────┤
│ URL Objetivo: https://ejemplo.com                               │
│ Fecha: 2025-06-29 19:53:28                                      │
│ Duración: 746ms                                                 │
├─────────────────────────────────────────────────────────────────┤
│ Tests Ejecutados: 3 | Pasados: 2 | Fallidos: 1                 │
│ Puntuación de Seguridad: 5.7/10 (Alto)                         │
└─────────────────────────────────────────────────────────────────┘
```

## 🏗️ Arquitectura del Proyecto

```
versaSecurityTest/
├── main.go                          # Punto de entrada principal
├── config.json                      # Configuración por defecto
├── README.md                        # Este archivo
├── go.mod                          # Definición del módulo Go
├── internal/
│   ├── config/
│   │   └── config.go               # Manejo de configuración
│   ├── scanner/
│   │   ├── scanner.go              # Lógica principal del scanner
│   │   └── tests/
│   │       └── basic.go            # Tests de seguridad implementados
│   └── report/
│       └── report.go               # Generación de reportes
└── versaSecurityTest.exe           # Binario compilado
```

## 🛠️ Desarrollo

### Agregar Nuevos Tests

Para implementar un nuevo test de seguridad:

1. **Crear el test** en `internal/scanner/tests/`:

```go
type MiNuevoTest struct{}

func (t *MiNuevoTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
    // Implementar lógica del test
    return TestResult{
        TestName:    "Mi Nuevo Test",
        Status:      "Passed", // o "Failed"
        Description: "Descripción del resultado",
        Severity:    "Medium",  // None, Low, Medium, High, Critical
        Details:     []string{},
        Evidence:    []Evidence{},
    }
}
```

2. **Registrar el test** en `scanner.go`:

```go
func (ws *WebScanner) getEnabledTests() []TestRunner {
    var testRunners []TestRunner
    
    // Tests existentes...
    
    if ws.config.Tests.MiNuevoTest {
        testRunners = append(testRunners, &tests.MiNuevoTest{})
    }
    
    return testRunners
}
```

3. **Agregar configuración** en `config.go`:

```go
type TestConfig struct {
    // Tests existentes...
    MiNuevoTest bool `json:"mi_nuevo_test"`
}
```

### Ejecutar Tests de Desarrollo

```bash
# Ejecutar tests unitarios
go test ./...

# Ejecutar con cobertura
go test -cover ./...

# Test de integración
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

Usa las [GitHub Issues](https://github.com/tuusuario/versaSecurityTest/issues) para reportar bugs, incluyendo:
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

- **GitHub Issues**: [Reportar problemas](https://github.com/tuusuario/versaSecurityTest/issues)
- **Documentación**: [Wiki del proyecto](https://github.com/tuusuario/versaSecurityTest/wiki)
- **Discusiones**: [GitHub Discussions](https://github.com/tuusuario/versaSecurityTest/discussions)

## 🎯 Roadmap

### Versión 1.1.0 (Próxima)
- [ ] Tests avanzados de SQL Injection
- [ ] Detección de vulnerabilidades CSRF
- [ ] Scanner de headers de seguridad completo
- [ ] Tests de autenticación y autorización

### Versión 1.2.0
- [ ] Soporte para SSL/TLS testing
- [ ] Tests de directory traversal
- [ ] Validación de subida de archivos
- [ ] API REST para integración

### Versión 2.0.0
- [ ] Interfaz web
- [ ] Base de datos de resultados
- [ ] Reportes programados
- [ ] Integración con CI/CD

## 🏆 Reconocimientos

- Inspirado en herramientas como OWASP ZAP y Nikto
- Desarrollado con las mejores prácticas de Go
- Agradecimientos a la comunidad de seguridad web

---

<div align="center">

**🔐 VersaSecurityTest - Porque la seguridad web importa**

[⭐ Dale una estrella si te gusta el proyecto](https://github.com/tuusuario/versaSecurityTest)

</div>
