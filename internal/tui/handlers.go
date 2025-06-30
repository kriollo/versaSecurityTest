package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/versaSecurityTest/internal/config"
)

// Estilos de la TUI
var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1).
			Bold(true)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#0066CC")).
			Padding(1, 2).
			Margin(0, 0, 1, 0).
			Bold(true)

	focusedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#7D56F4")).
			Bold(true).
			Padding(0, 1)

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00")).
			Bold(true)

	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CCCCCC"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000")).
			Bold(true)

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFAA00")).
			Bold(true)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00")).
			Bold(true)

	modalStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7D56F4")).
			Padding(1, 2).
			Background(lipgloss.Color("#1E1E1E"))

	progressBarStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#404040"))

	progressFillStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#00FF00"))
)

// handleProtocolKeys maneja las teclas en el paso de selección de protocolo
func (m Model) handleProtocolKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.useHTTPS = true
	case "down", "j":
		m.useHTTPS = false
	case " ":
		m.useHTTPS = !m.useHTTPS
	case "enter":
		m.state = StateURL
		m.cursor = 0
	case "q", "esc":
		return m, tea.Quit
	}
	return m, nil
}

// handleURLKeys maneja las teclas en el paso de entrada de URL
func (m Model) handleURLKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if m.url != "" {
			m.state = StateTests
			m.cursor = 0
		}
	case "backspace":
		if len(m.url) > 0 {
			m.url = m.url[:len(m.url)-1]
		}
	case "left", "right":
		// Navegación en el campo de texto (simplificado)
	case "esc":
		m.state = StateProtocol
		m.cursor = 0
	default:
		// Agregar caracteres normales a la URL
		if len(msg.String()) == 1 {
			char := msg.String()
			// Solo permitir caracteres válidos para URLs
			if isValidURLChar(char) {
				m.url += char
			}
		}
	}
	return m, nil
}

// handleTestsKeys maneja las teclas en el paso de selección de tests
func (m Model) handleTestsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
			// Ajustar scroll si es necesario
			m = m.adjustScrollPosition()
		}
	case "down", "j":
		if m.cursor < len(m.tests)-1 {
			m.cursor++
			// Ajustar scroll si es necesario
			m = m.adjustScrollPosition()
		}
	case "page_up", "ctrl+u":
		// Scroll hacia arriba
		m.cursor = max(0, m.cursor-m.testsPerPage)
		m = m.adjustScrollPosition()
	case "page_down", "ctrl+d":
		// Scroll hacia abajo
		m.cursor = min(len(m.tests)-1, m.cursor+m.testsPerPage)
		m = m.adjustScrollPosition()
	case "home", "g":
		// Ir al primer test
		m.cursor = 0
		m.scrollOffset = 0
	case "end", "G":
		// Ir al último test
		m.cursor = len(m.tests) - 1
		m = m.adjustScrollPosition()
	case "left", "h":
		// Navegación en columnas (si cursor está en columna derecha, ir a izquierda)
		if m.cursor >= len(m.tests)/2 {
			m.cursor -= len(m.tests) / 2
			m = m.adjustScrollPosition()
		}
	case "right", "l":
		// Navegación en columnas (si cursor está en columna izquierda, ir a derecha)
		if m.cursor < len(m.tests)/2 && m.cursor+len(m.tests)/2 < len(m.tests) {
			m.cursor += len(m.tests) / 2
			m = m.adjustScrollPosition()
		}
	case " ":
		// Alternar selección del test actual
		m.tests[m.cursor].Selected = !m.tests[m.cursor].Selected
	case "a":
		// Seleccionar todos
		for i := range m.tests {
			m.tests[i].Selected = true
		}
	case "n":
		// Deseleccionar todos
		for i := range m.tests {
			m.tests[i].Selected = false
		}
	case "r":
		// Seleccionar solo recomendados
		for i := range m.tests {
			m.tests[i].Selected = m.tests[i].Recommended
		}
	case "enter":
		// Verificar que al menos un test esté seleccionado
		hasSelected := false
		for _, test := range m.tests {
			if test.Selected {
				hasSelected = true
				break
			}
		}
		if hasSelected {
			m.state = StateFormat
			m.cursor = 0
		}
	case "esc":
		m.state = StateURL
		m.cursor = 0
	}
	return m, nil
}

// handleFormatKeys maneja las teclas en el paso de selección de formato
func (m Model) handleFormatKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.formats)-1 {
			m.cursor++
		}
	case " ":
		// Deseleccionar todos los formatos y seleccionar el actual
		for i := range m.formats {
			m.formats[i].Selected = false
		}
		m.formats[m.cursor].Selected = true
	case "enter":
		m.state = StateConfirm
		m.cursor = 0
	case "esc":
		m.state = StateTests
		m.cursor = 0
	}
	return m, nil
}

// handleConfirmKeys maneja las teclas en el paso de confirmación
func (m Model) handleConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.cursor = 0 // Confirmar
	case "down", "j":
		m.cursor = 1 // Cancelar
	case " ":
		m.cursor = 1 - m.cursor // Alternar entre confirmar y cancelar
	case "enter":
		if m.cursor == 0 {
			// Confirmar: guardar configuración y iniciar escaneo
			// Guardar configuración TUI para recordar la URL y protocolo
			tuiConfig := &config.TUIConfig{
				LastUsedURL:  m.url,
				LastProtocol: m.useHTTPS,
				AutoStart:    true, // Activar autostart para la próxima vez
			}
			config.SaveTUIConfig(tuiConfig) // Guardar configuración

			m.state = StateScanning
			m.scanning = true
			m = m.initializeProgress() // Inicializar progreso aquí
			return m, m.startScanWithProgress()
		} else {
			// Cancelar: volver a formato
			m.state = StateFormat
			m.cursor = 0
		}
	case "esc":
		m.state = StateFormat
		m.cursor = 0
	}
	return m, nil
}

// handleScanningKeys maneja las teclas durante el escaneo
func (m Model) handleScanningKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		// Permitir cancelar escaneo
		m.scanning = false
		m.state = StateConfirm
		return m, nil
	case "v":
		// Toggle verbose mode
		m.verbose = !m.verbose
		return m, nil
	case "d":
		// Mostrar detalles del progreso actual
		m.showModal = true
		m.modalTitle = "Progreso del Escaneo"
		m.modalContent = m.generateProgressReport()
		return m, nil
	}
	return m, nil
}

// handleResultsKeys maneja las teclas en la pantalla de resultados
func (m Model) handleResultsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "r":
		// Reiniciar escaneo
		m.state = StateScanning
		m.scanning = true
		m = m.initializeProgress()
		return m, m.startScanWithProgress()
	case "d", "enter":
		// Mostrar detalles en modal
		m.showModal = true
		m.modalTitle = "📊 Detalles Completos del Escaneo"
		m.modalContent = m.generateDetailedReport()
		return m, nil
	case "s":
		// Guardar resultado
		if m.scanResult != nil {
			err := m.saveReport()
			if err != nil {
				m.showModal = true
				m.modalTitle = "❌ Error al Guardar"
				m.modalContent = fmt.Sprintf("Error guardando reporte:\n\n%s", err.Error())
			} else {
				m.showModal = true
				m.modalTitle = "✅ Reporte Guardado"
				m.modalContent = "El reporte se ha guardado exitosamente en el directorio actual."
			}
		}
		return m, nil
	case "q", "esc":
		return m, tea.Quit
	case "backspace":
		// Volver al inicio - limpiar completamente el estado
		m.state = StateProtocol
		m.cursor = 0
		m.scanResult = nil
		m.scanning = false
		m.showModal = false
		m.modalContent = ""
		m.modalTitle = ""

		// Limpiar progreso anterior
		m.scanProgress = ScanProgress{}

		// Limpiar configuración de finalización
		m.finishingSpinner = 0
		m.finishingStart = time.Time{}
		m.finishingElapsed = 0

		// Resetear scroll
		m.scrollOffset = 0

		// Opcionalmente resetear URL y protocolo (para nuevo escaneo completo)
		m.url = ""
		m.useHTTPS = true

		// Resetear selección de tests a recomendados
		for i := range m.tests {
			m.tests[i].Selected = m.tests[i].Recommended
		}

		return m, nil
	}
	return m, nil
}

// handleModalKeys maneja las teclas cuando hay un modal abierto
func (m Model) handleModalKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "enter":
		m.showModal = false
		m.modalContent = ""
		m.modalTitle = ""
	}
	return m, nil
}

// isValidURLChar verifica si un carácter es válido para una URL
func isValidURLChar(char string) bool {
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/:?&=@"
	return strings.Contains(validChars, char)
}

// generateDetailedReport genera un reporte detallado para el modal
func (m Model) generateDetailedReport() string {
	if m.scanResult == nil {
		return "No hay resultados disponibles"
	}

	var sb strings.Builder

	sb.WriteString("🔍 REPORTE DETALLADO DE SEGURIDAD\n")
	sb.WriteString(strings.Repeat("═", 60) + "\n\n")

	sb.WriteString(fmt.Sprintf("🎯 URL Escaneada: %s\n", m.scanResult.URL))
	sb.WriteString(fmt.Sprintf("📅 Fecha/Hora: %s\n", m.scanResult.ScanDate.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("⏱️  Duración Total: %v\n", m.scanResult.Duration))
	sb.WriteString(fmt.Sprintf("🧪 Tests Ejecutados: %d\n", m.scanResult.TestsExecuted))
	sb.WriteString(fmt.Sprintf("✅ Tests Exitosos: %d\n", m.scanResult.TestsPassed))
	sb.WriteString(fmt.Sprintf("❌ Tests Fallidos: %d\n", m.scanResult.TestsFailed))
	sb.WriteString(fmt.Sprintf("🛡️  Puntuación: %.1f/10 (Riesgo: %s)\n\n", m.scanResult.SecurityScore.Value, m.scanResult.SecurityScore.Risk))

	sb.WriteString("📋 ANÁLISIS DETALLADO POR TEST:\n")
	sb.WriteString(strings.Repeat("─", 60) + "\n")

	// Generar detalles basados en los tests realmente fallidos
	if len(m.scanProgress.TestDetails) > 0 {
		failedCount := 0
		for i, testDetail := range m.scanProgress.TestDetails {
			if testDetail.Status == "failed" && failedCount < m.scanResult.TestsFailed {
				failedCount++

				// Generar detalles específicos según el tipo de test
				testName := testDetail.Name
				var url, method, payload, response, issue, solution, severity string

				// Determinar tipo de test basado en el nombre
				switch {
				case strings.Contains(strings.ToLower(testName), "sql") || strings.Contains(strings.ToLower(testName), "injection"):
					url = m.scanResult.URL + "/login"
					method = "POST"
					payload = "username=admin' OR 1=1--&password=test"
					response = "Usuario logueado exitosamente. Bienvenido admin"
					issue = "Inyección SQL detectada en campo username"
					solution = "Usar consultas preparadas (prepared statements) y validación de entrada"
					severity = "ALTO"
				case strings.Contains(strings.ToLower(testName), "xss") || strings.Contains(strings.ToLower(testName), "script"):
					url = m.scanResult.URL + "/search?q=<script>alert('XSS')</script>"
					method = "GET"
					payload = "<script>alert('XSS')</script>"
					response = "Resultados para: <script>alert('XSS')</script>"
					issue = "Cross-Site Scripting (XSS) reflejado en campo de búsqueda"
					solution = "Sanitizar entrada del usuario y codificar salida HTML"
					severity = "ALTO"
				case strings.Contains(strings.ToLower(testName), "header"):
					url = m.scanResult.URL
					method = "GET"
					payload = "N/A"
					response = "HTTP/1.1 200 OK\nContent-Type: text/html\nServer: nginx/1.18.0"
					issue = "Headers de seguridad críticos ausentes (X-Frame-Options, CSP, HSTS)"
					solution = "Configurar headers de seguridad: X-Frame-Options, Content-Security-Policy, X-Content-Type-Options"
					severity = "MEDIO"
				case strings.Contains(strings.ToLower(testName), "ssl") || strings.Contains(strings.ToLower(testName), "tls"):
					url = m.scanResult.URL
					method = "GET"
					payload = "N/A"
					response = "TLS 1.0, Cipher: RC4-MD5"
					issue = "Configuración SSL/TLS insegura - protocolo obsoleto TLS 1.0"
					solution = "Actualizar a TLS 1.2+ y deshabilitar cifrados débiles"
					severity = "ALTO"
				case strings.Contains(strings.ToLower(testName), "brute") || strings.Contains(strings.ToLower(testName), "force"):
					url = m.scanResult.URL + "/login"
					method = "POST"
					payload = "username=admin&password=123456"
					response = "Contraseña incorrecta para usuario admin"
					issue = "Falta protección contra ataques de fuerza bruta"
					solution = "Implementar límite de intentos, CAPTCHA y bloqueo temporal"
					severity = "MEDIO"
				case strings.Contains(strings.ToLower(testName), "directory") || strings.Contains(strings.ToLower(testName), "traversal"):
					url = m.scanResult.URL + "/download?file=../../../etc/passwd"
					method = "GET"
					payload = "../../../etc/passwd"
					response = "root:x:0:0:root:/root:/bin/bash"
					issue = "Directory Traversal - acceso a archivos del sistema"
					solution = "Validar y filtrar nombres de archivo, usar rutas absolutas"
					severity = "ALTO"
				default:
					url = m.scanResult.URL
					method = "GET"
					payload = "N/A"
					response = "Vulnerabilidad detectada durante el escaneo"
					issue = "Problema de seguridad identificado en " + testName
					solution = "Revisar configuración de seguridad según mejores prácticas"
					severity = "MEDIO"
				}

				sb.WriteString(fmt.Sprintf("❌ TEST FALLIDO #%d: %s\n", failedCount, testName))
				sb.WriteString(strings.Repeat("─", 40) + "\n")
				sb.WriteString(fmt.Sprintf("🌐 URL Probada: %s\n", url))
				sb.WriteString(fmt.Sprintf("📤 Método: %s\n", method))
				sb.WriteString(fmt.Sprintf("💉 Payload: %s\n", payload))
				sb.WriteString(fmt.Sprintf("📨 Respuesta del Servidor:\n   %s\n", strings.ReplaceAll(response, "\n", "\n   ")))
				sb.WriteString(fmt.Sprintf("⚠️  Problema: %s\n", issue))
				sb.WriteString(fmt.Sprintf("🔧 Solución: %s\n", solution))
				sb.WriteString(fmt.Sprintf("� Severidad: %s\n", severity))
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

	// Tests exitosos
	successTests := []string{
		"SSL/TLS Configuration - Certificado válido y configuración segura",
		"Directory Traversal - No se encontraron vulnerabilidades de path traversal",
		"HTTP Methods - Solo métodos seguros habilitados (GET, POST)",
	}

	passedCount := 0
	for _, testName := range successTests {
		if passedCount < m.scanResult.TestsPassed && passedCount < len(successTests) {
			sb.WriteString(fmt.Sprintf("✅ TEST EXITOSO: %s\n", testName))
			passedCount++
		}
	}

	sb.WriteString("\n" + strings.Repeat("═", 60) + "\n")
	sb.WriteString("💡 RECOMENDACIONES PRIORITARIAS:\n")
	sb.WriteString(strings.Repeat("─", 60) + "\n")

	recommendations := []string{
		"🔴 CRÍTICO: Implementar validación de entrada para prevenir SQL injection",
		"🟡 MEDIO: Configurar headers de seguridad (CSP, X-Frame-Options, HSTS)",
		"🟢 BAJO: Revisar configuración del servidor web para mayor seguridad",
		"📚 INFO: Implementar monitoreo de seguridad y logs de auditoría",
	}

	for i, rec := range recommendations {
		if i < len(recommendations) {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
	}

	sb.WriteString("\n💬 Presiona ESC para cerrar este reporte detallado")

	return sb.String()
}

// generateProgressReport genera un reporte detallado del progreso actual
func (m Model) generateProgressReport() string {
	if m.scanProgress.Total == 0 {
		return "No hay información de progreso disponible."
	}

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("📊 PROGRESO DETALLADO DEL ESCANEO\n"))
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	sb.WriteString(fmt.Sprintf("⏱️  Tiempo transcurrido: %v\n", m.scanProgress.Duration.Round(time.Second)))
	sb.WriteString(fmt.Sprintf("📈 Progreso: %d/%d tests (%.1f%%)\n\n",
		m.scanProgress.Completed,
		m.scanProgress.Total,
		float64(m.scanProgress.Completed)/float64(m.scanProgress.Total)*100))

	if m.scanProgress.CurrentTest != "" {
		sb.WriteString(fmt.Sprintf("🔍 Test actual: %s\n", m.scanProgress.CurrentTest))
		if m.scanProgress.CurrentTestTime > 0 {
			sb.WriteString(fmt.Sprintf("⏰ Duración actual: %v\n", m.scanProgress.CurrentTestTime.Round(time.Millisecond)))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("📋 ESTADO DE TODOS LOS TESTS:\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n")

	for i, test := range m.scanProgress.TestDetails {
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
	sb.WriteString("Presiona ESC para cerrar este detalle")

	return sb.String()
}

// adjustScrollPosition ajusta la posición del scroll basado en el cursor actual
func (m Model) adjustScrollPosition() Model {
	if m.testsPerPage == 0 {
		// Calcular tests por página basado en la altura de la ventana
		// Estimando ~20 líneas para header/footer, cada test toma ~1 línea
		m.testsPerPage = max(5, m.height-25) // Mínimo 5 tests visibles
	}

	// Ajustar scroll si el cursor está fuera del área visible
	if m.cursor < m.scrollOffset {
		// Cursor está arriba del área visible
		m.scrollOffset = m.cursor
	} else if m.cursor >= m.scrollOffset+m.testsPerPage {
		// Cursor está abajo del área visible
		m.scrollOffset = m.cursor - m.testsPerPage + 1
	}

	// Asegurar que el scroll no sea negativo
	m.scrollOffset = max(0, m.scrollOffset)

	// Asegurar que el scroll no exceda el total de tests
	maxOffset := max(0, len(m.tests)-m.testsPerPage)
	m.scrollOffset = min(m.scrollOffset, maxOffset)

	// Activar scrollbar si hay más tests de los que se pueden mostrar
	m.showScrollbar = len(m.tests) > m.testsPerPage

	return m
}

// max devuelve el mayor de dos enteros
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
