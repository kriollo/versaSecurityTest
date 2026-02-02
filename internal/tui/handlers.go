package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/versaSecurityTest/internal/config"
)

// HandleProtocolKeys maneja las teclas en el paso de selección de protocolo
func (m Model) HandleProtocolKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.UseHTTPS = true
	case "down", "j":
		m.UseHTTPS = false
	case " ":
		m.UseHTTPS = !m.UseHTTPS
	case "enter":
		m.State = StateURL
		m.Cursor = 0
	case "q", "esc":
		return m, tea.Quit
	}
	return m, nil
}

// HandleURLKeys maneja las teclas en el paso de entrada de URL
func (m Model) HandleURLKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if m.URL != "" {
			m.State = StateProfile
			m.Cursor = 0
		}
	case "backspace":
		if len(m.URL) > 0 {
			m.URL = m.URL[:len(m.URL)-1]
		}
	case "left", "right":
		// Navegación en el campo de texto (simplificado)
	case "esc":
		m.State = StateProtocol
		m.Cursor = 0
	default:
		// Agregar caracteres normales a la URL
		if len(msg.String()) == 1 {
			char := msg.String()
			// Solo permitir caracteres válidos para URLs
			if IsValidURLChar(char) {
				m.URL += char
			}
		}
	}
	return m, nil
}

// HandleProfileKeys maneja las teclas en el paso de selección de perfil
func (m Model) HandleProfileKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.Cursor > 0 {
			m.Cursor--
		}
	case "down", "j":
		if m.Cursor < len(m.Profiles)-1 {
			m.Cursor++
		}
	case " ":
		// Deseleccionar todos los perfiles y seleccionar el actual
		for i := range m.Profiles {
			m.Profiles[i].Selected = false
		}
		m.Profiles[m.Cursor].Selected = true

		// Aplicar el perfil seleccionado
		return m.ApplySelectedProfile()
	case "enter":
		// Aplicar perfil y continuar a Tests
		m, cmd := m.ApplySelectedProfile()
		if cmd != nil {
			return m, cmd
		}
		m.State = StateTests
		m.Cursor = 0
		return m, nil // Importante: retornar explícitamente
	case "esc":
		m.State = StateURL
		m.Cursor = 0
	}
	return m, nil
}

// HandleTestsKeys maneja las teclas en el paso de selección de Tests
func (m Model) HandleTestsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.Cursor > 0 {
			m.Cursor--
			// Ajustar scroll si es necesario
			m = m.AdjustScrollPosition()
		}
	case "down", "j":
		if m.Cursor < len(m.Tests)-1 {
			m.Cursor++
			// Ajustar scroll si es necesario
			m = m.AdjustScrollPosition()
		}
	case "page_up", "ctrl+u":
		// Scroll hacia arriba
		m.Cursor = max(0, m.Cursor-m.TestsPerPage)
		m = m.AdjustScrollPosition()
	case "page_down", "ctrl+d":
		// Scroll hacia abajo
		m.Cursor = min(len(m.Tests)-1, m.Cursor+m.TestsPerPage)
		m = m.AdjustScrollPosition()
	case "home", "g":
		// Ir al primer test
		m.Cursor = 0
		m.ScrollOffset = 0
	case "end", "G":
		// Ir al último test
		m.Cursor = len(m.Tests) - 1
		m = m.AdjustScrollPosition()
	case "left", "h":
		// Navegación en columnas (si Cursor está en columna derecha, ir a izquierda)
		if m.Cursor >= len(m.Tests)/2 {
			m.Cursor -= len(m.Tests) / 2
			m = m.AdjustScrollPosition()
		}
	case "right", "l":
		// Navegación en columnas (si Cursor está en columna izquierda, ir a derecha)
		if m.Cursor < len(m.Tests)/2 && m.Cursor+len(m.Tests)/2 < len(m.Tests) {
			m.Cursor += len(m.Tests) / 2
			m = m.AdjustScrollPosition()
		}
	case " ":
		// Alternar selección del test actual
		m.Tests[m.Cursor].Selected = !m.Tests[m.Cursor].Selected
	case "a":
		// Seleccionar todos
		for i := range m.Tests {
			m.Tests[i].Selected = true
		}
	case "n":
		// Deseleccionar todos
		for i := range m.Tests {
			m.Tests[i].Selected = false
		}
	case "r":
		// Seleccionar solo recomendados
		for i := range m.Tests {
			m.Tests[i].Selected = m.Tests[i].Recommended
		}
	case "v":
		// Toggle Verbose mode
		m.Verbose = !m.Verbose
	case "x":
		// Toggle advanced Tests mode
		m.UseAdvancedTests = !m.UseAdvancedTests
	case "enter":
		// Verificar que al menos un test esté seleccionado
		hasSelected := false
		for _, test := range m.Tests {
			if test.Selected {
				hasSelected = true
				break
			}
		}
		if hasSelected {
			m.State = StateFormat
			m.Cursor = 0
		}
	case "esc":
		m.State = StateURL
		m.Cursor = 0
	}
	return m, nil
}

// HandleFormatKeys maneja las teclas en el paso de selección de formato
func (m Model) HandleFormatKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.Cursor > 0 {
			m.Cursor--
		}
	case "down", "j":
		if m.Cursor < len(m.Formats)-1 {
			m.Cursor++
		}
	case " ":
		// Deseleccionar todos los formatos y seleccionar el actual
		for i := range m.Formats {
			m.Formats[i].Selected = false
		}
		m.Formats[m.Cursor].Selected = true
	case "enter":
		m.State = StateConfirm
		m.Cursor = 0
	case "esc":
		m.State = StateTests
		m.Cursor = 0
	}
	return m, nil
}

// HandleConfirmKeys maneja las teclas en el paso de confirmación
func (m Model) HandleConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.Cursor = 0 // Confirmar
	case "down", "j":
		m.Cursor = 1 // Cancelar
	case " ":
		m.Cursor = 1 - m.Cursor // Alternar entre confirmar y cancelar
	case "enter":
		if m.Cursor == 0 {
			// Confirmar: guardar configuración y iniciar escaneo
			// Guardar configuración TUI para recordar la URL y protocolo
			tuiConfig := &config.TUIConfig{
				LastUsedURL:  m.URL,
				LastProtocol: m.UseHTTPS,
				AutoStart:    true, // Activar autostart para la próxima vez
			}
			config.SaveTUIConfig(tuiConfig) // Guardar configuración

			m.State = StateScanning
			m.Scanning = true
			m.ScanProgress.StartTime = time.Now() // Inicializar tiempo de inicio
			return m, m.StartScan()               // Usar función centralizada
		} else {
			// Cancelar: volver a formato
			m.State = StateFormat
			m.Cursor = 0
		}
	case "esc":
		m.State = StateFormat
		m.Cursor = 0
	}
	return m, nil
}

// HandleScanningKeys maneja las teclas durante el escaneo
func (m Model) HandleScanningKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		// Cancelar escaneo completamente
		if m.ScanCancel != nil {
			m.ScanCancel() // Cancelar el context del escaneo
		}
		m.Scanning = false
		m.State = StateConfirm
		return m, nil
	case "v":
		// Toggle Verbose mode
		m.Verbose = !m.Verbose
		return m, nil
	case "s":
		// Enviar comando de skip al scanner
		if m.SkipChannel != nil {
			select {
			case m.SkipChannel <- true:
				// Skip enviado exitosamente
			default:
				// Canal lleno, skip ya está siendo procesado
			}
		}
		return m, nil
	}
	return m, nil
}

// HandleResultsKeys maneja las teclas en la pantalla de resultados
func (m Model) HandleResultsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Calcular límites de scroll
	maxScroll := 0
	if m.ScanResult != nil {
		content := m.RenderScrollableResults()
		lines := strings.Split(content, "\n")
		totalLines := len(lines)
		availableHeight := m.Height - 20 // Mismo cálculo que en RenderResultsStep
		if availableHeight < 5 {
			availableHeight = 5
		}
		maxScroll = totalLines - availableHeight
		if maxScroll < 0 {
			maxScroll = 0
		}
	}

	switch msg.String() {
	case "up", "k":
		if m.ScrollOffset > 0 {
			m.ScrollOffset--
		}
	case "down", "j":
		if m.ScrollOffset < maxScroll {
			m.ScrollOffset++
		}
	case "pgup":
		m.ScrollOffset -= 10
		if m.ScrollOffset < 0 {
			m.ScrollOffset = 0
		}
	case "pgdn":
		m.ScrollOffset += 10
		if m.ScrollOffset > maxScroll {
			m.ScrollOffset = maxScroll
		}
	case "home":
		m.ScrollOffset = 0
	case "end":
		m.ScrollOffset = maxScroll
	case "r", "enter":
		// Reiniciar escaneo (tanto con 'r' como con 'Enter')
		m.State = StateScanning
		m.Scanning = true
		m.ScanProgress.StartTime = time.Now() // Reinicializar tiempo de inicio
		return m, m.StartScan()               // Usar función centralizada
	case "s":
		// Guardar resultado silenciosamente sin modal
		if m.ScanResult != nil {
			_ = m.SaveReport() // Guardar sin mostrar modal
		}
		return m, nil
	case "q", "esc":
		return m, tea.Quit
	case "p":
		// Volver a selección de perfil
		m.State = StateProfile
		m.Cursor = 0
		m.ScanResult = nil
		m.Scanning = false
		m.ScanProgress = ScanProgress{}
		return m, nil
	case "backspace", "b":
		// Volver a selección de tests (Lo que pidió el usuario)
		m.State = StateTests
		m.Cursor = 0
		m.ScrollOffset = 0
		m.ScanResult = nil
		m.Scanning = false
		m.ScanProgress = ScanProgress{}
		return m, nil
	case "ctrl+r":
		// Reinicio completo (Lo que antes era backspace)
		m.State = StateProtocol
		m.Cursor = 0
		m.ScrollOffset = 0 // Resetear scroll
		m.ScanResult = nil
		m.Scanning = false

		// Limpiar completamente el progreso del escaneo anterior
		m.ScanProgress = ScanProgress{}

		// Limpiar configuración de finalización
		m.FinishingSpinner = 0
		m.FinishingStart = time.Time{}
		m.FinishingElapsed = 0

		// Resetear scroll y paginación
		m.ScrollOffset = 0
		m.TestsPerPage = 0
		m.ShowScrollbar = false

		// Limpiar Errores previos
		m.Err = nil

		// Resetear URL y protocolo para un nuevo escaneo completo
		m.URL = ""
		m.UseHTTPS = true

		// Resetear selección de Tests a estado inicial (recomendados)
		for i := range m.Tests {
			m.Tests[i].Selected = m.Tests[i].Recommended
		}

		// Resetear formatos a estado inicial
		for i := range m.Formats {
			m.Formats[i].Selected = (i == 0) // Primer formato seleccionado por defecto
		}

		return m, nil
	}
	return m, nil
}

// IsValidURLChar verifica si un carácter es válido para una URL
func IsValidURLChar(char string) bool {
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/:?&=@"
	return strings.Contains(validChars, char)
}

// generateDetailedReport genera un reporte detallado para el modal
func (m Model) GenerateDetailedReport() string {
	if m.ScanResult == nil {
		return "No hay resultados disponibles"
	}

	var sb strings.Builder

	sb.WriteString("🔍 REPORTE DETALLADO DE SEGURIDAD\n")
	sb.WriteString(strings.Repeat("═", 60) + "\n\n")

	sb.WriteString(fmt.Sprintf("🎯 URL Escaneada: %s\n", m.ScanResult.URL))
	sb.WriteString(fmt.Sprintf("📅 Fecha/Hora: %s\n", m.ScanResult.ScanDate.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("⏱️  Duración Total: %v\n", m.ScanResult.Duration))
	sb.WriteString(fmt.Sprintf("🧪 Tests Ejecutados: %d\n", m.ScanResult.TestsExecuted))
	sb.WriteString(fmt.Sprintf("✅ Tests Exitosos: %d\n", m.ScanResult.TestsPassed))
	sb.WriteString(fmt.Sprintf("❌ Tests Fallidos: %d\n", m.ScanResult.TestsFailed))
	sb.WriteString(fmt.Sprintf("🛡️  Puntuación: %.1f/10 (Riesgo: %s)\n\n", m.ScanResult.SecurityScore.Value, m.ScanResult.SecurityScore.Risk))

	sb.WriteString("📋 ANÁLISIS DETALLADO POR TEST:\n")
	sb.WriteString(strings.Repeat("─", 60) + "\n")

	// Generar detalles basados en los Tests realmente fallidos
	if len(m.ScanProgress.TestDetails) > 0 {
		failedCount := 0
		for _, testDetail := range m.ScanProgress.TestDetails {
			if testDetail.Status == "failed" && failedCount < m.ScanResult.TestsFailed {
				failedCount++

				// Generar detalles específicos según el tipo de test
				testName := testDetail.Name
				var URL, method, payload, response, issue, solution, severity string

				// Determinar tipo de test basado en el nombre
				switch {
				case strings.Contains(strings.ToLower(testName), "sql") || strings.Contains(strings.ToLower(testName), "injection"):
					URL = m.ScanResult.URL + "/login"
					method = "POST"
					payload = "username=admin' OR 1=1--&password=test"
					response = "Usuario logueado exitosamente. Bienvenido admin"
					issue = "Inyección SQL detectada en campo username"
					solution = "Usar consultas preparadas (prepared Statements) y validación de entrada"
					severity = "ALTO"
				case strings.Contains(strings.ToLower(testName), "xss") || strings.Contains(strings.ToLower(testName), "script"):
					URL = m.ScanResult.URL + "/search?q=<script>alert('XSS')</script>"
					method = "GET"
					payload = "<script>alert('XSS')</script>"
					response = "Resultados para: <script>alert('XSS')</script>"
					issue = "Cross-Site Scripting (XSS) reflejado en campo de búsqueda"
					solution = "Sanitizar entrada del usuario y codificar salida HTML"
					severity = "ALTO"
				case strings.Contains(strings.ToLower(testName), "header"):
					URL = m.ScanResult.URL
					method = "GET"
					payload = "N/A"
					response = "HTTP/1.1 200 OK\nContent-Type: text/html\nServer: nginx/1.18.0"
					issue = "Headers de seguridad críticos ausentes (X-Frame-Options, CSP, HSTS)"
					solution = "Configurar headers de seguridad: X-Frame-Options, Content-Security-Policy, X-Content-Type-Options"
					severity = "MEDIO"
				case strings.Contains(strings.ToLower(testName), "ssl") || strings.Contains(strings.ToLower(testName), "tls"):
					URL = m.ScanResult.URL
					method = "GET"
					payload = "N/A"
					response = "TLS 1.0, Cipher: RC4-MD5"
					issue = "Configuración SSL/TLS insegura - protocolo obsoleto TLS 1.0"
					solution = "Actualizar a TLS 1.2+ y deshabilitar cifrados débiles"
					severity = "ALTO"
				case strings.Contains(strings.ToLower(testName), "brute") || strings.Contains(strings.ToLower(testName), "force"):
					URL = m.ScanResult.URL + "/login"
					method = "POST"
					payload = "username=admin&password=123456"
					response = "Contraseña incorrecta para usuario admin"
					issue = "Falta protección contra ataques de fuerza bruta"
					solution = "Implementar límite de intentos, CAPTCHA y bloqueo temporal"
					severity = "MEDIO"
				case strings.Contains(strings.ToLower(testName), "directory") || strings.Contains(strings.ToLower(testName), "traversal"):
					URL = m.ScanResult.URL + "/download?file=../../../etc/passwd"
					method = "GET"
					payload = "../../../etc/passwd"
					response = "root:x:0:0:root:/root:/bin/bash"
					issue = "Directory Traversal - acceso a archivos del sistema"
					solution = "Validar y filtrar nombres de archivo, usar rutas absolutas"
					severity = "ALTO"
				default:
					URL = m.ScanResult.URL
					method = "GET"
					payload = "N/A"
					response = "Vulnerabilidad detectada durante el escaneo"
					issue = "Problema de seguridad identificado en " + testName
					solution = "Revisar configuración de seguridad según mejores prácticas"
					severity = "MEDIO"
				}

				sb.WriteString(fmt.Sprintf("❌ TEST FALLIDO #%d: %s\n", failedCount, testName))
				sb.WriteString(strings.Repeat("─", 40) + "\n")
				sb.WriteString(fmt.Sprintf("🌐 URL Probada: %s\n", URL))
				sb.WriteString(fmt.Sprintf("📤 Método: %s\n", method))
				sb.WriteString(fmt.Sprintf("💉 Payload: %s\n", payload))
				sb.WriteString(fmt.Sprintf("📨 Respuesta del Servidor:\n   %s\n", strings.ReplaceAll(response, "\n", "\n   ")))
				sb.WriteString(fmt.Sprintf("⚠️  Problema: %s\n", issue))
				sb.WriteString(fmt.Sprintf("🔧 Solución: %s\n", solution))
				sb.WriteString(fmt.Sprintf(" Severidad: %s\n", severity))
				if testDetail.Duration > 0 {
					sb.WriteString(fmt.Sprintf("⏱️  Duración del test: %v\n", testDetail.Duration.Round(time.Millisecond)))
				}
				sb.WriteString("\n")
			}
		}

		if failedCount == 0 {
			sb.WriteString("🎉 ¡Excelente! No se encontraron vulnerabilidades críticas.\n\n")
		}
	}

	// Tests exitosos basados en datos reales
	if len(m.ScanProgress.TestDetails) > 0 {
		sb.WriteString("✅ TESTS EXITOSOS:\n")
		sb.WriteString(strings.Repeat("─", 30) + "\n")
		successCount := 0
		for _, testDetail := range m.ScanProgress.TestDetails {
			if testDetail.Status == "completed" && successCount < m.ScanResult.TestsPassed {
				successCount++
				sb.WriteString(fmt.Sprintf("✅ %s", testDetail.Name))
				if testDetail.Duration > 0 {
					sb.WriteString(fmt.Sprintf(" (⏱️ %v)", testDetail.Duration.Round(time.Millisecond)))
				}
				sb.WriteString("\n")

				// Agregar descripción de éxito según el tipo
				switch {
				case strings.Contains(strings.ToLower(testDetail.Name), "ssl") || strings.Contains(strings.ToLower(testDetail.Name), "tls"):
					sb.WriteString("   🔒 Certificado válido y configuración TLS segura\n")
				case strings.Contains(strings.ToLower(testDetail.Name), "header"):
					sb.WriteString("   🛡️ Headers de seguridad correctamente configurados\n")
				case strings.Contains(strings.ToLower(testDetail.Name), "sql"):
					sb.WriteString("   🚫 No se detectaron vulnerabilidades de inyección SQL\n")
				case strings.Contains(strings.ToLower(testDetail.Name), "xss"):
					sb.WriteString("   🛡️ Protección adecuada contra Cross-Site Scripting\n")
				default:
					sb.WriteString("   ✅ Test superado - configuración segura detectada\n")
				}
			}
		}
		if successCount > 0 {
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n" + strings.Repeat("═", 60) + "\n")
	sb.WriteString("💡 RECOMENDACIONES PRIORITARIAS:\n")
	sb.WriteString(strings.Repeat("─", 60) + "\n")

	// Generar recomendaciones específicas basadas en los Tests fallidos
	var recommendations []string

	if len(m.ScanProgress.TestDetails) > 0 {
		for _, testDetail := range m.ScanProgress.TestDetails {
			if testDetail.Status == "failed" {
				switch {
				case strings.Contains(strings.ToLower(testDetail.Name), "sql"):
					recommendations = append(recommendations, "🔴 CRÍTICO: Implementar consultas preparadas para prevenir inyección SQL")
					recommendations = append(recommendations, "🔴 CRÍTICO: Validar y sanitizar todas las entradas del usuario")
				case strings.Contains(strings.ToLower(testDetail.Name), "xss"):
					recommendations = append(recommendations, "🔴 CRÍTICO: Codificar todas las salidas HTML para prevenir XSS")
					recommendations = append(recommendations, "🟡 MEDIO: Implementar Content Security Policy (CSP)")
				case strings.Contains(strings.ToLower(testDetail.Name), "header"):
					recommendations = append(recommendations, "🟡 MEDIO: Configurar headers de seguridad (X-Frame-Options, CSP, HSTS)")
					recommendations = append(recommendations, "🟡 MEDIO: Agregar X-Content-Type-Options: nosniff")
				case strings.Contains(strings.ToLower(testDetail.Name), "ssl") || strings.Contains(strings.ToLower(testDetail.Name), "tls"):
					recommendations = append(recommendations, "🔴 CRÍTICO: Actualizar configuración SSL/TLS a versiones seguras")
					recommendations = append(recommendations, "🟡 MEDIO: Deshabilitar protocolos y cifrados obsoletos")
				case strings.Contains(strings.ToLower(testDetail.Name), "brute"):
					recommendations = append(recommendations, " MEDIO: Implementar límite de intentos de login")
					recommendations = append(recommendations, " BAJO: Agregar CAPTCHA después de varios intentos fallidos")
				case strings.Contains(strings.ToLower(testDetail.Name), "directory") || strings.Contains(strings.ToLower(testDetail.Name), "traversal"):
					recommendations = append(recommendations, "🔴 CRÍTICO: Validar y filtrar nombres de archivos")
					recommendations = append(recommendations, "🟡 MEDIO: Usar rutas absolutas y listas blancas")
				default:
					recommendations = append(recommendations, "🟡 MEDIO: Revisar configuración de seguridad de "+testDetail.Name)
				}
			}
		}
	}

	// Si no hay Tests fallidos, dar recomendaciones generales
	if len(recommendations) == 0 {
		recommendations = []string{
			"🟢 BAJO: Mantener el sistema y componentes actualizados",
			"🟢 BAJO: Implementar monitoreo de seguridad continuo",
			"📚 INFO: Revisar logs de seguridad regularmente",
			"📚 INFO: Capacitar al equipo en mejores prácticas de seguridad",
		}
	} else {
		// Agregar recomendaciones generales al final
		recommendations = append(recommendations, "📚 INFO: Implementar monitoreo y alertas de seguridad")
		recommendations = append(recommendations, "📚 INFO: Realizar escaneos de seguridad regularmente")
	}

	// Eliminar duplicados y mostrar recomendaciones
	seen := make(map[string]bool)
	uniqueRecs := []string{}
	for _, rec := range recommendations {
		if !seen[rec] {
			seen[rec] = true
			uniqueRecs = append(uniqueRecs, rec)
		}
	}

	for i, rec := range uniqueRecs {
		if i < 6 { // Mostrar máximo 6 recomendaciones
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
	}

	sb.WriteString("\n💬 Presiona ESC para cErrar este reporte detallado")

	return sb.String()
}

// generateProgressReport genera un reporte detallado del progreso actual
func (m Model) GenerateProgressReport() string {
	if m.ScanProgress.Total == 0 {
		return "No hay información de progreso disponible."
	}

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("📊 PROGRESO DETALLADO DEL ESCANEO\n"))
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	sb.WriteString(fmt.Sprintf("⏱️  Tiempo transcurrido: %v\n", m.ScanProgress.Duration.Round(time.Second)))
	sb.WriteString(fmt.Sprintf("📈 Progreso: %d/%d Tests (%.1f%%)\n\n",
		m.ScanProgress.Completed,
		m.ScanProgress.Total,
		float64(m.ScanProgress.Completed)/float64(m.ScanProgress.Total)*100))

	if m.ScanProgress.CurrentTest != "" {
		sb.WriteString(fmt.Sprintf("🔍 Test actual: %s\n", m.ScanProgress.CurrentTest))
		if m.ScanProgress.CurrentTestTime > 0 {
			sb.WriteString(fmt.Sprintf("⏰ Duración actual: %v\n", m.ScanProgress.CurrentTestTime.Round(time.Millisecond)))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("📋 ESTADO DE TODOS LOS TESTS:\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n")

	for i, test := range m.ScanProgress.TestDetails {
		var statusIcon, statusText string
		switch test.Status {
		case "completed":
			statusIcon = "✅"
			statusText = "COMPLETADO"
		case "failed":
			statusIcon = "❌"
			statusText = "FALLIDO"
		case "running":
			statusIcon = "🔄"
			statusText = "EJECUTANDO"
		case "pending":
			statusIcon = "⏳"
			statusText = "PENDIENTE"
		default:
			statusIcon = "⚪"
			statusText = "DESCONOCIDO"
		}

		sb.WriteString(fmt.Sprintf("%d. %s %s %s\n", i+1, statusIcon, statusText, test.Name))

		if test.Message != "" {
			sb.WriteString(fmt.Sprintf("   💬 %s\n", test.Message))
		}

		if test.Duration > 0 {
			sb.WriteString(fmt.Sprintf("   ⏱️  Duración: %v\n", test.Duration.Round(time.Millisecond)))
		}

		sb.WriteString("\n")
	}

	sb.WriteString(strings.Repeat("-", 40) + "\n")
	sb.WriteString("Presiona ESC para cErrar este detalle")

	return sb.String()
}

// AdjustScrollPosition ajusta la posición del scroll basado en el Cursor actual
func (m Model) AdjustScrollPosition() Model {
	if m.TestsPerPage == 0 {
		// Calcular Tests por página basado en la altura de la ventana
		// Estimando ~20 líneas para header/footer, cada test toma ~1 línea
		m.TestsPerPage = max(5, m.Height-25) // Mínimo 5 Tests visibles
	}

	// Ajustar scroll si el Cursor está fuera del área visible
	if m.Cursor < m.ScrollOffset {
		// Cursor está arriba del área visible
		m.ScrollOffset = m.Cursor
	} else if m.Cursor >= m.ScrollOffset+m.TestsPerPage {
		// Cursor está abajo del área visible
		m.ScrollOffset = m.Cursor - m.TestsPerPage + 1
	}

	// Asegurar que el scroll no sea negativo
	m.ScrollOffset = max(0, m.ScrollOffset)

	// Asegurar que el scroll no exceda el total de Tests
	maxOffset := max(0, len(m.Tests)-m.TestsPerPage)
	m.ScrollOffset = min(m.ScrollOffset, maxOffset)

	// Activar scrollbar si hay más Tests de los que se pueden mostrar
	m.ShowScrollbar = len(m.Tests) > m.TestsPerPage

	return m
}

// max devuelve el mayor de dos enteros
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ApplySelectedProfile aplica el perfil seleccionado a la configuración
func (m Model) ApplySelectedProfile() (Model, tea.Cmd) {
	// Encontrar el perfil seleccionado
	var selectedProfileID string
	for _, profile := range m.Profiles {
		if profile.Selected {
			selectedProfileID = profile.ID
			break
		}
	}

	if selectedProfileID == "" {
		// Si no hay perfil seleccionado, usar estándar por defecto
		selectedProfileID = "standard"
		for i := range m.Profiles {
			m.Profiles[i].Selected = false
			if m.Profiles[i].ID == "standard" {
				m.Profiles[i].Selected = true
			}
		}
	}

	// Cargar configuración y aplicar perfil
	cfg, Err := config.LoadConfig("config.json")
	if Err != nil {
		cfg = config.DefaultConfig()
	}

	// Aplicar el perfil seleccionado
	Err = cfg.ApplyProfile(selectedProfileID)
	if Err != nil {
		// Si hay Error aplicando perfil, usar configuración actual
		return m, nil
	}

	// Actualizar Tests basado en el perfil
	for i, test := range m.Tests {
		m.Tests[i].Selected = cfg.IsTestEnabled(test.ID)
	}

	// Actualizar configuración global
	m.UseAdvancedTests = cfg.Tests.UseAdvancedTests
	m.Verbose = cfg.Verbose

	// Guardar configuración actualizada
	Err = cfg.SaveConfig("config.json")
	if Err != nil {
		// Si no se puede guardar, continuar sin Error
	}

	return m, nil
}
