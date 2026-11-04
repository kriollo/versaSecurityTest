package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	tests "github.com/versaSecurityTest/internal/scanner/tests"
	"github.com/versaSecurityTest/internal/version"
)

// RenderHeader renderiza el header de la aplicación
func (m Model) RenderHeader() string {
	banner := `
  🛡️  VERSA SECURITY
  ──────────────────`

	header := HeaderStyle.Render(banner)
	versionLabel := NormalStyle.Render("   " + version.Label() + " | Simple & Secure")

	return header + "\n" + versionLabel + "\n"
}

// RenderProtocolStep renderiza el paso de selección de protocolo
func (m Model) RenderProtocolStep() string {
	var sb strings.Builder

	sb.WriteString(TitleStyle.Render(" ¿Cómo debemos conectar con el sitio? "))
	sb.WriteString("\n\n")
	sb.WriteString("Seleccione el protocolo de seguridad:\n\n")

	// Opción HTTPS
	httpsMarker := IconCircle
	if m.UseHTTPS {
		httpsMarker = IconCheck
	}
	httpsStyle := NormalStyle
	if m.UseHTTPS {
		httpsStyle = FocusedStyle
	}
	sb.WriteString(httpsStyle.Render(fmt.Sprintf(" %s HTTPS (Recomendado) ", httpsMarker)))
	sb.WriteString("\n")

	// Opción HTTP
	httpMarker := IconCircle
	if !m.UseHTTPS {
		httpMarker = IconCheck
	}
	httpStyle := NormalStyle
	if !m.UseHTTPS {
		httpStyle = FocusedStyle
	}
	sb.WriteString(httpStyle.Render(fmt.Sprintf(" %s HTTP (Solo desarrollo) ", httpMarker)))
	sb.WriteString("\n\n")

	sb.WriteString("💡 Recomendación: Use HTTPS para sitios en internet.\n")

	return sb.String()
}

// RenderURLStep renderiza el paso de entrada de URL
func (m Model) RenderURLStep() string {
	var sb strings.Builder

	sb.WriteString(TitleStyle.Render(" ¿Qué sitio quieres analizar? "))
	sb.WriteString("\n\n")

	protocol := "https://"
	if !m.UseHTTPS {
		protocol = "http://"
	}

	sb.WriteString(fmt.Sprintf("Usando: %s\n\n", SuccessStyle.Render(protocol)))
	sb.WriteString("Escribe la dirección del sitio (ejemplo: google.com):\n\n")

	sb.WriteString(FocusedStyle.Render(fmt.Sprintf(" > %s%s ", protocol, m.URL)))
	sb.WriteString("\n\n")

	sb.WriteString("💡 Puedes escribir un dominio o una IP local.")

	return sb.String()
}

// RenderProfileStep renderiza el paso de selección de perfil
func (m Model) RenderProfileStep() string {
	var sb strings.Builder

	sb.WriteString(TitleStyle.Render(" ¿Qué tan profundo quieres buscar? "))
	sb.WriteString("\n\n")

	for i, profile := range m.Profiles {
		marker := IconCircle
		style := NormalStyle
		card := CardStyle
		if profile.Selected {
			marker = IconDiamond
			style = SelectedStyle
		}
		if i == m.Cursor {
			card = CardFocusStyle
		}

		content := fmt.Sprintf("%s %s\n%s\n%s",
			marker, profile.Name,
			NormalStyle.Render(profile.Description),
			style.Render(fmt.Sprintf("⏱️  %v | 🔄 x%d | 🎯 %d Tests",
				profile.Timeout, profile.Concurrent, profile.TestCount)))

		sb.WriteString(card.Render(content))
		sb.WriteString("\n")
	}

	return sb.String()
}

// RenderTestsStep renderiza el paso de selección de Tests
func (m Model) RenderTestsStep() string {
	var sb strings.Builder

	sb.WriteString(TitleStyle.Render(" ¿Qué pruebas quieres realizar? "))
	sb.WriteString("\n\n")

	if len(m.Tests) == 0 {
		sb.WriteString(ErrorStyle.Render(" ⚠️ No hay pruebas disponibles "))
		return sb.String()
	}

	sb.WriteString("Selecciona las categorías de seguridad:\n\n")

	// Mostrar Tests en columnas para mejor visualización
	sb.WriteString(m.RenderTestsInColumns())

	// Mostrar estadísticas
	selectedCount := 0
	for _, test := range m.Tests {
		if test.Selected {
			selectedCount++
		}
	}

	sb.WriteString(fmt.Sprintf("\n📊 %d seleccionados de %d disponibles\n", selectedCount, len(m.Tests)))

	if selectedCount == 0 {
		sb.WriteString(WarningStyle.Render(" ⚠️ Debes elegir al menos una prueba "))
	}

	return sb.String()
}

// RenderTestsInColumns renderiza los Tests en columnas
func (m Model) RenderTestsInColumns() string {
	var sb strings.Builder

	const columnsCount = 2
	const columnWidth = 35

	for i := 0; i < len(m.Tests); i += columnsCount {
		for col := 0; col < columnsCount && i+col < len(m.Tests); col++ {
			idx := i + col
			test := m.Tests[idx]

			marker := IconCircle
			style := NormalStyle
			if test.Selected {
				marker = IconCheck
				style = SelectedStyle
			}
			if idx == m.Cursor {
				style = FocusedStyle
			}

			// Truncar nombre si es muy largo
			displayName := test.Name
			if len(displayName) > columnWidth-6 {
				displayName = displayName[:columnWidth-9] + "..."
			}

			testLine := style.Render(fmt.Sprintf(" %s %s", marker, displayName))

			// Añadir padding para alinear columnas
			padding := columnWidth - len(fmt.Sprintf("%s %s", marker, displayName))
			if padding > 0 {
				testLine += strings.Repeat(" ", padding)
			}

			sb.WriteString(testLine)

			if col < columnsCount-1 && i+col+1 < len(m.Tests) {
				sb.WriteString("  ")
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// RenderFormatStep renderiza el paso de selección de formato
func (m Model) RenderFormatStep() string {
	var sb strings.Builder

	sb.WriteString(TitleStyle.Render(" ¿Cómo quieres el reporte? "))
	sb.WriteString("\n\n")

	for i, format := range m.Formats {
		marker := IconCircle
		style := NormalStyle
		if format.Selected {
			marker = IconCheck
			style = SelectedStyle
		}
		if i == m.Cursor {
			style = FocusedStyle
		}

		sb.WriteString(style.Render(fmt.Sprintf(" %s %s ", marker, format.Name)))
		sb.WriteString("\n")
		sb.WriteString(NormalStyle.Render(fmt.Sprintf("    %s", format.Description)))
		sb.WriteString("\n\n")
	}

	return sb.String()
}

// RenderConfirmStep renderiza el paso de confirmación
func (m Model) RenderConfirmStep() string {
	var sb strings.Builder

	sb.WriteString(TitleStyle.Render(" ¿Todo listo para empezar? "))
	sb.WriteString("\n\n")

	protocol := "https://"
	if !m.UseHTTPS {
		protocol = "http://"
	}

	content := fmt.Sprintf("🎯 Objetivo: %s%s\n", protocol, m.URL)

	selectedProfile := "Estándar"
	for _, profile := range m.Profiles {
		if profile.Selected {
			selectedProfile = profile.Name
			break
		}
	}
	content += fmt.Sprintf("⚙️  Modo: %s\n", selectedProfile)

	selectedCount := 0
	for _, test := range m.Tests {
		if test.Selected {
			selectedCount++
		}
	}
	content += fmt.Sprintf("🎯 Pruebas: %d seleccionadas", selectedCount)

	sb.WriteString(CardStyle.Render(content))
	sb.WriteString("\n\n")

	sb.WriteString(SuccessStyle.Render(" 🚀 Presiona ENTER para iniciar el análisis "))
	sb.WriteString("\n")
	sb.WriteString(NormalStyle.Render("    o ESC para cambiar algo"))

	return sb.String()
}

// RenderScanningStep renderiza el paso de escaneo
func (m Model) RenderScanningStep() string {
	var sb strings.Builder

	sb.WriteString(TitleStyle.Render(" ANALIZANDO SEGURIDAD... "))
	sb.WriteString("\n\n")

	// Barra de progreso visual
	if m.ScanProgress.Total > 0 {
		percent := float64(m.ScanProgress.Completed) / float64(m.ScanProgress.Total) * 100

		progressBarWidth := 50
		filledWidth := int(percent / 100 * float64(progressBarWidth))
		if filledWidth > progressBarWidth {
			filledWidth = progressBarWidth
		}

		bar := strings.Repeat("█", filledWidth)
		if filledWidth < progressBarWidth {
			bar += strings.Repeat("░", progressBarWidth-filledWidth)
		}

		sb.WriteString(fmt.Sprintf("  %s  %.0f%%\n\n", SuccessStyle.Render(bar), percent))
	}

	sb.WriteString(fmt.Sprintf("  %s %s\n", IconSearch, NormalStyle.Render(m.ScanProgress.CurrentTest)))

	elapsed := time.Since(m.ScanProgress.StartTime)
	sb.WriteString(fmt.Sprintf("  %s %v transcurridos\n\n", IconClock, elapsed.Round(time.Second)))

	sb.WriteString(WarningStyle.Render("  ⚠️ Presiona 'q' para detener el análisis"))

	return sb.String()
}

// renderFinishingStep renderiza el paso de finalización
func (m Model) renderFinishingStep() string {
	var sb strings.Builder

	sb.WriteString(TitleStyle.Render("FINALIZANDO ESCANEO..."))
	sb.WriteString("\n\n")

	sb.WriteString("🔄 Generando reporte...\n")
	sb.WriteString("📊 Calculando puntuación de seguridad...\n")
	sb.WriteString("💾 Guardando resultados...\n\n")

	sb.WriteString(NormalStyle.Render("Por favor espere..."))

	return sb.String()
}

// RenderFinishingStep renderiza el estado de finalización
func (m Model) RenderFinishingStep() string {
	var sb strings.Builder

	sb.WriteString(TitleStyle.Render(" GENERANDO RESULTADOS FINALES... "))
	sb.WriteString("\n\n")

	// Spinner simple
	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinner := spinners[m.FinishingSpinner%len(spinners)]

	sb.WriteString(fmt.Sprintf("  %s %s\n\n", SuccessStyle.Render(spinner), NormalStyle.Render("Analizando vulnerabilidades encontradas...")))

	// Tiempo transcurrido
	elapsed := time.Since(m.FinishingStart)
	sb.WriteString(fmt.Sprintf("  ⏱️  %v transcurridos\n", elapsed.Round(time.Second)))

	return sb.String()
}

// RenderResultsStep renderiza los resultados del escaneo
func (m Model) RenderResultsStep() string {
	var sb strings.Builder

	if m.ScanResult == nil {
		sb.WriteString(ErrorStyle.Render(" ❌ No hay resultados disponibles "))
		return sb.String()
	}

	sb.WriteString(TitleStyle.Render(" ANÁLISIS COMPLETADO "))
	sb.WriteString("\n\n")

	// Card de Salud de Seguridad
	riskColor := ColorSuccess
	if m.ScanResult.SecurityScore.Value < 7 {
		riskColor = ColorWarning
	}
	if m.ScanResult.SecurityScore.Value < 4 {
		riskColor = ColorDanger
	}

	healthCard := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(riskColor).
		Padding(1, 2).
		MarginBottom(1).
		Render(fmt.Sprintf("🛡️  PUNTUACIÓN DE SEGURIDAD: %.1f / 10\nEstado: %s",
			m.ScanResult.SecurityScore.Value, m.ScanResult.SecurityScore.Risk))

	sb.WriteString(healthCard)
	sb.WriteString("\n\n")

	// Resumen rápido
	sb.WriteString(fmt.Sprintf(" %s %s | %s %s\n\n",
		IconCheck, SuccessStyle.Render(fmt.Sprintf("%d Pasados", m.ScanResult.TestsPassed)),
		IconCritical, ErrorStyle.Render(fmt.Sprintf("%d Fallidos", m.ScanResult.TestsFailed))))

	// Mostrar notificación si es reciente (menos de 5 segundos)
	if m.LastNotification != "" && time.Since(m.NotificationTime) < 5*time.Second {
		notificationStyle := lipgloss.NewStyle().
			Foreground(ColorPrimary).
			Background(ColorBoxBg).
			Bold(true).
			Padding(0, 1).
			Border(lipgloss.NormalBorder()).
			BorderForeground(ColorPrimary)

		sb.WriteString(notificationStyle.Render(" " + m.LastNotification + " "))
		sb.WriteString("\n\n")
	}

	// Scroll de detalles...

	// Contenido con scroll mejorado
	content := m.RenderScrollableResults()

	// Calcular dimensiones para scroll
	lines := strings.Split(content, "\n")
	totalLines := len(lines)
	availableHeight := m.Height - 20 // Reservar espacio para header y footer

	if availableHeight < 5 {
		availableHeight = 5
	}

	startLine := m.ScrollOffset
	endLine := startLine + availableHeight

	if endLine > totalLines {
		endLine = totalLines
	}

	// Asegurar que startLine no sea mayor que totalLines
	if startLine >= totalLines && totalLines > 0 {
		startLine = totalLines - availableHeight
		if startLine < 0 {
			startLine = 0
		}
	}

	// Mostrar líneas visibles
	var scrollContent string
	if startLine < totalLines && endLine > startLine {
		visibleLines := lines[startLine:endLine]
		scrollContent = strings.Join(visibleLines, "\n")
	} else {
		scrollContent = "No hay contenido para mostrar"
	}

	// Agregar indicadores de scroll visuales e intuitivos
	if totalLines > availableHeight {
		// Indicadores llamativos arriba y abajo
		if m.ScrollOffset > 0 {
			scrollContent = "▲▲▲ HAY MÁS CONTENIDO ARRIBA - Presiona ↑ o PgUp ▲▲▲\n" + scrollContent
		}

		if endLine < totalLines {
			scrollContent += "\n▼▼▼ HAY MÁS CONTENIDO ABAJO - Presiona ↓ o PgDn ▼▼▼"
		}

		// Barra de progreso visual
		progressPercent := float64(endLine) / float64(totalLines) * 100
		progressBar := "["
		barWidth := 20
		filled := int(progressPercent / 100 * float64(barWidth))

		// Asegurar que filled esté en el rango válido
		if filled < 0 {
			filled = 0
		}
		if filled > barWidth {
			filled = barWidth
		}

		for i := 0; i < barWidth; i++ {
			if i < filled {
				progressBar += "█"
			} else {
				progressBar += "░"
			}
		}
		progressBar += "]"

		scrollContent += fmt.Sprintf("\n\n📜 SCROLL: %s %.1f%% | Líneas %d-%d de %d",
			progressBar, progressPercent, startLine+1, endLine, totalLines)
		scrollContent += fmt.Sprintf("\n🎮 ↑↓ Línea | Enter: Reintentar | ← Borrar: Cambiar Tests | p: Perfil | s: Guardar | Esc: Salir")
	}

	sb.WriteString(scrollContent)

	return sb.String()
}

// RenderScrollableResults genera el contenido completo de resultados para scroll
func (m Model) RenderScrollableResults() string {
	var sb strings.Builder

	if len(m.ScanResult.TestResults) == 0 {
		sb.WriteString("✅ No se encontraron vulnerabilidades.\n")
		return sb.String()
	}

	// Mostrar resultados por test
	failedResults := []tests.TestResult{}
	passedResults := []tests.TestResult{}

	for _, result := range m.ScanResult.TestResults {
		if result.Status == "Failed" {
			failedResults = append(failedResults, result)
		} else {
			passedResults = append(passedResults, result)
		}
	}

	// Mostrar Tests fallidos primero
	if len(failedResults) > 0 {
		sb.WriteString(ErrorStyle.Render("🚨 TESTS FALLIDOS"))
		sb.WriteString("\n")
		sb.WriteString(strings.Repeat("=", 50))
		sb.WriteString("\n\n")

		for i, result := range failedResults {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, result.TestName))
			sb.WriteString(fmt.Sprintf("   📋 Descripción: %s\n", result.Description))
			sb.WriteString(fmt.Sprintf("   ⚠️  Severidad: %s\n", result.Severity))
			if len(result.Evidence) > 0 {
				sb.WriteString(fmt.Sprintf("   🔍 Evidencia: %s\n", result.Evidence[0].Payload))
			}
			if len(result.Details) > 0 {
				sb.WriteString(fmt.Sprintf("   📝 Detalles: %s\n", strings.Join(result.Details, ", ")))
			}
			sb.WriteString("\n")
		}
	}

	// Mostrar Tests pasados
	if len(passedResults) > 0 {
		sb.WriteString(SuccessStyle.Render("✅ TESTS PASADOS"))
		sb.WriteString("\n")
		sb.WriteString(strings.Repeat("=", 50))
		sb.WriteString("\n\n")

		for i, result := range passedResults {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, result.TestName))
			sb.WriteString(fmt.Sprintf("   📋 Descripción: %s\n", result.Description))
			sb.WriteString(fmt.Sprintf("   ✅ Estado: %s\n", result.Status))
			sb.WriteString("\n")
		}
	}

	// Información adicional
	sb.WriteString(strings.Repeat("=", 50))
	sb.WriteString("\n")
	sb.WriteString(SuccessStyle.Render("📊 RESUMEN DE SEGURIDAD"))
	sb.WriteString("\n\n")

	if len(failedResults) > 0 {
		sb.WriteString("🚨 CRÍTICO: Se encontraron vulnerabilidades que deben ser resueltas.\n")
	} else {
		sb.WriteString("✅ EXCELENTE: No se encontraron vulnerabilidades críticas.\n")
	}

	sb.WriteString(fmt.Sprintf("\n📄 Reporte completo guardado en: reports/\n"))
	sb.WriteString(fmt.Sprintf("📈 Puntuación de seguridad: %.1f/10\n", m.ScanResult.SecurityScore.Value))

	return sb.String()
}

// RenderFooter renderiza el footer con ayuda contextual
func (m Model) RenderFooter() string {
	var help strings.Builder

	switch m.State {
	case StateURL:
		help.WriteString("🎮 Tab: Cambiar protocolo | Enter: Continuar | Esc: Salir")
	case StateProfile:
		help.WriteString("🎮 ↑↓: Navegar perfiles | Enter: Seleccionar | Esc: Volver")
	case StateTests:
		help.WriteString("🎮 ↑↓: Navegar | Space: Seleccionar/Deseleccionar | a: Todos | n: Ninguno | Enter: Continuar | Esc: Volver")
	case StateFormat:
		help.WriteString("🎮 ↑↓: Navegar formatos | Enter: Continuar | Esc: Volver")
	case StateConfirm:
		help.WriteString("🎮 Enter: Iniciar escaneo | Esc: Volver")
	case StateScanning:
		help.WriteString("🎮 q: Cancelar escaneo | Ctrl+C: Salir forzado")
	case StateResults:
		help.WriteString("🎮 Enter: Reintentar | ← Borrar: Cambiar Tests | p: Perfil | ↑↓: Scroll | s: Guardar | Esc: Salir")
	default:
		help.WriteString("🎮 Navegación con ↑↓ | Enter: Seleccionar | Esc: Volver/Salir")
	}

	return NormalStyle.Render(help.String())
}

// renderModal renderiza un modal centrado
func (m Model) renderModal(content string) string {
	modal := ModalStyle.Render(content)

	// Centrar el modal
	lines := strings.Split(modal, "\n")
	modalHeight := len(lines)
	modalWidth := 0
	for _, line := range lines {
		if len(line) > modalWidth {
			modalWidth = len(line)
		}
	}

	// Calcular posición centrada con valores mínimos de 0
	topPadding := (m.Height - modalHeight) / 2
	if topPadding < 0 {
		topPadding = 0
	}

	leftPadding := (m.Width - modalWidth) / 2
	if leftPadding < 0 {
		leftPadding = 0
	}

	var result strings.Builder

	// Añadir padding superior
	for i := 0; i < topPadding; i++ {
		result.WriteString("\n")
	}

	// Añadir contenido con padding izquierdo
	for _, line := range lines {
		// Doble verificación para evitar valores negativos
		safePadding := leftPadding
		if safePadding < 0 {
			safePadding = 0
		}
		result.WriteString(strings.Repeat(" ", safePadding))
		result.WriteString(line)
		result.WriteString("\n")
	}

	return result.String()
}
