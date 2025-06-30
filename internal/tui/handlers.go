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
		}
	case "down", "j":
		if m.cursor < len(m.tests)-1 {
			m.cursor++
		}
	case "left", "h":
		// Navegación en columnas (si cursor está en columna derecha, ir a izquierda)
		if m.cursor >= len(m.tests)/2 {
			m.cursor -= len(m.tests) / 2
		}
	case "right", "l":
		// Navegación en columnas (si cursor está en columna izquierda, ir a derecha)
		if m.cursor < len(m.tests)/2 && m.cursor+len(m.tests)/2 < len(m.tests) {
			m.cursor += len(m.tests) / 2
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
		// Volver al inicio
		m.state = StateProtocol
		m.cursor = 0
		m.scanResult = nil
		m.scanning = false
		// Limpiar progreso anterior
		m.scanProgress = ScanProgress{}
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

	sb.WriteString(fmt.Sprintf("URL Escaneada: %s\n", m.scanResult.URL))
	sb.WriteString(fmt.Sprintf("Fecha: %s\n", m.scanResult.ScanDate.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Duración: %v\n", m.scanResult.Duration))
	sb.WriteString(fmt.Sprintf("Tests Ejecutados: %d\n", m.scanResult.TestsExecuted))
	sb.WriteString(fmt.Sprintf("Tests Pasados: %d\n", m.scanResult.TestsPassed))
	sb.WriteString(fmt.Sprintf("Tests Fallidos: %d\n", m.scanResult.TestsFailed))
	sb.WriteString(fmt.Sprintf("Puntuación: %.1f/10 (%s)\n\n", m.scanResult.SecurityScore.Value, m.scanResult.SecurityScore.Risk))

	if len(m.scanResult.TestResults) > 0 {
		sb.WriteString("Resultados por Test:\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		for _, result := range m.scanResult.TestResults {
			status := "❌ FALLÓ"
			if result.Status == "Passed" {
				status = "✅ PASÓ"
			}
			sb.WriteString(fmt.Sprintf("%s %s\n", status, result.TestName))
			if result.Description != "" {
				sb.WriteString(fmt.Sprintf("   %s\n", result.Description))
			}
			if len(result.Evidence) > 0 && m.verbose {
				sb.WriteString("   Evidencia:\n")
				for _, evidence := range result.Evidence {
					sb.WriteString(fmt.Sprintf("   - %s: %s\n", evidence.Type, evidence.Response))
				}
			}
			sb.WriteString("\n")
		}
	}

	if len(m.scanResult.Recommendations) > 0 {
		sb.WriteString("Recomendaciones:\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		for i, rec := range m.scanResult.Recommendations {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
	}

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
