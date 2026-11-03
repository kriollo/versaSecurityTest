# 🔐 VersaSecurityTest

**VersaSecurityTest** es un scanner de seguridad web automático desarrollado en Go, diseñado para identificar vulnerabilidades comunes en aplicaciones web de manera rápida y eficiente.

![VersaSecurityTest Banner](https://img.shields.io/badge/VersaSecurityTest-v2.1.0-blue.svg)
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
- **Vulnerabilidades conocidas (CVE 2026)**: Sondas de solo lectura para las fallas de 2026 en frameworks PHP (Laravel, Symfony, WordPress): configuración expuesta, credenciales no-string que rompen la petición, inyección de plantilla y código PHP servido como texto.
- **Directory Traversal**: Detección de vulnerabilidades de path traversal.
- **Network Port Scan**: Escaneo de puertos abiertos y servicios (A01:2021).
- **OWASP Top 10 2021**: Integración profunda con A06 (Componentes Vulnerables), A08 (Integridad) y A10 (SSRF Avanzado).
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
- `Enter`: Reintentar/Reiniciar escaneo actual (en resultados)
- `Backspace/B`: Volver a Selección de Tests (en resultados)
- `P`: Volver a Selección de Perfil (en resultados)
- `Ctrl+R`: Reinicio completo (Volver al inicio)
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

## 📈 Prueba de Capacidad (`load`)

Mide cuántos usuarios simultáneos aguanta una aplicación. Cada usuario virtual tiene sus propias
cookies, inicia sesión con su propio usuario (token CSRF incluido) y recorre las rutas indicadas
mientras la carga sube por etapas.

```bash
./versaSecurity load -url http://staging.ejemplo.cl \
  -users-file carga-usuarios.csv \
  -stages 10:30s,50:30s,100:30s,200:30s \
  -paths /admin/dashboard,/admin/perfiluser,xhr:/admin/api/session/heartbeat
```

```
usuarios peticiones    req/s       p50       p95       p99       máx  errores estados
     10       316     21.1       7ms      13ms     257ms     426ms     0.0% 200×316
     50      1500    100.0       7ms     250ms     996ms    1248ms     0.0% 200×1500
    200      4562    304.1       7ms    2029ms    3774ms    4135ms     0.0% 200×4562

📈 Capacidad: 100 usuarios simultáneos (p95 812ms). Con 200 se pasó de los umbrales.
```

- **Una sola IP:** cada usuario envía una IP distinta en `X-Forwarded-For` (`-spoof-ip`, activo por defecto).
  El servidor debe confiar en ese encabezado desde la máquina de la prueba; en versaWYS:
  `"trusted_proxies": ["IP-de-la-máquina-de-prueba"]` en el `config.json` del entorno de prueba.
  Sin eso, el límite de intentos de login bloquea a partir del quinto usuario (429).
- **Usuarios:** CSV `email,password`. En versaWYS: `php versaCLI app:user:load --count=200`
  (y `--delete` al terminar).
- **Rutas:** separadas por coma; `xhr:` las pide como el frontend (JSON). Un 3xx, 4xx o 5xx cuenta como error.
- **Umbrales:** una etapa vale si `p95 ≤ -max-p95` (1s) y errores `≤ -max-errors` (1%). El informe JSON
  queda en `reports/carga_<fecha>.json`.
- `-think` (500ms) es la pausa entre peticiones de un usuario: bájala para más presión por usuario.

> ⚠️ Es tráfico real de muchos usuarios: úsala contra un servidor propio o de prueba, nunca contra uno ajeno.

## 💥 Prueba de Resiliencia ante DoS (`flood`)

Comprueba si la app aguanta un flujo intenso desde muchas IP: si su límite de peticiones lo contiene
(responde 429) o si se degrada (5xx, timeouts). Es una prueba de **defensa**, no un ataque.

```bash
./versaSecurity flood -url http://staging.ejemplo.cl -path /admin/login -workers 200 -duration 30s
```

```
Peticiones: 16945 (2824 req/s)  p50 15ms  p95 40ms  p99 182ms  máx 692ms
  2xx/3xx: 16945  |  429 (frenadas): 0  |  5xx: 0  |  errores de red: 0
⚠️  La app sirvió todo el flujo sin frenarlo (sin 429); las IP rotadas pueden evadir el límite por IP.
```

- `-rotate-ip` (por defecto) envía una IP distinta por petición en `X-Forwarded-For`: prueba si el límite
  **por IP** se puede evadir rotando el origen (el caso de un ataque distribuido). Con `-rotate-ip=false`
  todo sale de una IP y debería dispararse el límite global (429).
- El veredicto distingue entre *la app frenó el abuso* (429, bien), *se rompió* (5xx) o *se cayó* (timeouts).
- Informe JSON en `reports/flood_<fecha>.json`.

> ⚠️ Envía tráfico real de alto volumen. Solo contra servidores propios o con autorización expresa
> (fuera de `localhost` exige la bandera `-yes`).

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

## 🔄 Actualización (`-update`)

```bash
./versaSecurity -update
```

Consulta la última versión publicada en GitHub y, si hay una nueva:

- **Binario instalado**: descarga el binario del release para tu sistema (SO/arquitectura) y reemplaza el
  ejecutable actual. En Windows el `.exe` en uso se renombra y se pone el nuevo en su lugar.
- **Clon de desarrollo** (hay carpeta `.git`): ofrece `git pull` + recompilar.

En ambos casos pide confirmación antes de tocar nada.

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

### ✅ Versión 2.1.0 (Actual)

- [x] **Prueba de capacidad** (`load`): usuarios virtuales concurrentes con login y su propia IP
- [x] **Prueba de resiliencia ante DoS** (`flood`): mide si el rate limiting contiene el abuso
- [x] **Test de vulnerabilidades conocidas** (CVE 2026 de frameworks PHP), seleccionable en la TUI
- [x] **Self-update real** del binario (`-update`) con detección de SO/arquitectura
- [x] **Backoff ante 429**: un test que dispara el rate limiter no bloquea los demás
- [x] **Resultados reales**: lectura correcta de códigos HTTP y fin de falsos positivos

### Versión 2.0.1

- [x] **Integración profunda con OWASP Top 10 2021** (A06, A08, A10)
- [x] **Network Port Scanner** concurrente integrado
- [x] **Navegación TUI Granular** (Backspace para tests, P para perfiles)
- [x] **Selección de Tests Granular** en la interfaz
- [x] **Unificación completa CLI/TUI**
- [x] **Perfiles de escaneo** (Básico, Estándar, Avanzado)
- [x] **Guardado silencioso de reportes**

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

**🔐 VersaSecurityTest v2.1.0 - Scanner de Seguridad con integración OWASP 2021**

**✨ Versión 2.0**: OWASP 2021 (A06, A08, A10), Port Scanner, Navegación Granular, TUI Profesional

[⭐ Dale una estrella si te gusta el proyecto](https://github.com/kriollo/versaSecurityTest)

</div>
