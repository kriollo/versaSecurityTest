package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/versaSecurityTest/internal/scanner/tests"
)

// renderHeader renderiza el header de la aplicación
func (m Model) renderHeader() string {
	banner := `
██╗   ██╗███████╗██████╗ ███████╗ █████╗ ███████╗███████╗ ██████╗
██║   ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║   ██║█████╗  ██████╔╝███████╗███████║███████╗█████╗  ██║
╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══██║╚════██║██╔══╝  ██║
 ╚████╔╝ ███████╗██║  ██║███████║██║  ██║███████║███████╗╚██████╗
  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝`

	header := headerStyle.Render(banner)
	version := normalStyle.Render("v1.1.0 - Security Testing Tool")

	return header + "\n" + version + "\n"
}

// renderProtocolStep renderiza el paso de selección de protocolo
func (m Model) renderProtocolStep() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("PASO 1: SELECCIÓN DE PROTOCOLO"))
	sb.WriteString("\n\n")
	sb.WriteString("Seleccione el protocolo a usar:\n\n")

	// Opción HTTPS
	httpsMarker := "[ ]"
	if m.useHTTPS {
		httpsMarker = "[X]"
	}
	httpsStyle := normalStyle
	if m.useHTTPS {
		httpsStyle = focusedStyle
	}
	sb.WriteString(httpsStyle.Render(fmt.Sprintf("%s HTTPS (Recomendado)", httpsMarker)))
	sb.WriteString("\n")

	// Opción HTTP
	httpMarker := "[ ]"
	if !m.useHTTPS {
		httpMarker = "[X]"
	}
	httpStyle := normalStyle
	if !m.useHTTPS {
		httpStyle = focusedStyle
	}
	sb.WriteString(httpStyle.Render(fmt.Sprintf("%s HTTP", httpMarker)))
	sb.WriteString("\n\n")

	sb.WriteString("💡 Consejo: HTTPS es más seguro y se recomienda para sitios de producción.\n")
	sb.WriteString("   Use HTTP solo para desarrollo local (localhost).\n")

	return sb.String()
}

// renderURLStep renderiza el paso de entrada de URL
func (m Model) renderURLStep() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("PASO 2: INGRESE LA URL O DOMINIO"))
	sb.WriteString("\n\n")

	protocol := "https://"
	if !m.useHTTPS {
		protocol = "http://"
	}

	sb.WriteString(fmt.Sprintf("Protocolo seleccionado: %s\n\n", successStyle.Render(protocol)))
	sb.WriteString("Ingrese la URL objetivo (sin protocolo):\n")
	sb.WriteString("Ejemplos: localhost:8080, www.ejemplo.com, api.ejemplo.com/v1\n\n")

	sb.WriteString(fmt.Sprintf("URL completa: %s%s\n", protocol, m.url))
	sb.WriteString(focusedStyle.Render(fmt.Sprintf("Escriba aquí: %s", m.url)))
	sb.WriteString("\n\n")

	sb.WriteString("💡 Ejemplos:\n")
	sb.WriteString("   • example.com\n")
	sb.WriteString("   • www.example.com\n")
	sb.WriteString("   • example.com:8080\n")
	sb.WriteString("   • 192.168.1.100\n")

	return sb.String()
}

// renderProfileStep renderiza el paso de selección de perfil
func (m Model) renderProfileStep() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("PASO 3: SELECCIÓN DE PERFIL DE ESCANEO"))
	sb.WriteString("\n\n")
	sb.WriteString("Seleccione el perfil de escaneo:\n\n")

	for i, profile := range m.profiles {
		marker := "[ ]"
		style := normalStyle
		if profile.Selected {
			marker = "[X]"
			style = selectedStyle
		}
		if i == m.cursor {
			style = focusedStyle
		}

		sb.WriteString(style.Render(fmt.Sprintf("%s %s", marker, profile.Name)))
		sb.WriteString("\n")
		sb.WriteString(style.Render(fmt.Sprintf("    %s", profile.Description)))
		sb.WriteString("\n")
		sb.WriteString(style.Render(fmt.Sprintf("    ⏱️  Timeout: %v | 🔄 Concurrencia: %d | 🎯 Tests: %d activos",
			profile.Timeout, profile.Concurrent, profile.TestCount)))
		sb.WriteString("\n\n")
	}

	sb.WriteString("💡 Consejos:\n")
	sb.WriteString("   • Básico: Rápido y esencial para evaluaciones iniciales\n")
	sb.WriteString("   • Estándar: Equilibrio entre velocidad y cobertura\n")
	sb.WriteString("   • Avanzado: Escaneo completo y exhaustivo\n")

	return sb.String()
}

// renderTestsStep renderiza el paso de selección de tests
func (m Model) renderTestsStep() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("PASO 4: SELECCIÓN DE TESTS"))
	sb.WriteString("\n\n")

	if len(m.tests) == 0 {
		sb.WriteString(errorStyle.Render("⚠️  No hay tests disponibles"))
		return sb.String()
	}

	sb.WriteString("Seleccione los tests a ejecutar:\n\n")

	// Mostrar tests en columnas para mejor visualización
	sb.WriteString(m.renderTestsInColumns())

	// Mostrar estadísticas
	selectedCount := 0
	for _, test := range m.tests {
		if test.Selected {
			selectedCount++
		}
	}

	sb.WriteString(fmt.Sprintf("\n📊 Tests seleccionados: %d de %d disponibles\n", selectedCount, len(m.tests)))

	if selectedCount == 0 {
		sb.WriteString(warningStyle.Render("⚠️  Debe seleccionar al menos un test para continuar"))
	}

	return sb.String()
}

// renderTestsInColumns renderiza los tests en columnas
func (m Model) renderTestsInColumns() string {
	var sb strings.Builder

	const columnsCount = 2
	const columnWidth = 35

	for i := 0; i < len(m.tests); i += columnsCount {
		for col := 0; col < columnsCount && i+col < len(m.tests); col++ {
			idx := i + col
			test := m.tests[idx]

			marker := "[ ]"
			style := normalStyle
			if test.Selected {
				marker = "[X]"
			}
			if idx == m.cursor {
				style = focusedStyle
			}

			// Truncar nombre si es muy largo
			displayName := test.Name
			if len(displayName) > columnWidth-6 {
				displayName = displayName[:columnWidth-9] + "..."
			}

			testLine := style.Render(fmt.Sprintf("%s %s", marker, displayName))

			// Añadir padding para alinear columnas
			padding := columnWidth - len(fmt.Sprintf("%s %s", marker, displayName))
			if padding > 0 {
				testLine += strings.Repeat(" ", padding)
			}

			sb.WriteString(testLine)

			if col < columnsCount-1 && i+col+1 < len(m.tests) {
				sb.WriteString("  ")
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// renderFormatStep renderiza el paso de selección de formato
func (m Model) renderFormatStep() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("PASO 5: FORMATO DE REPORTE"))
	sb.WriteString("\n\n")
	sb.WriteString("Seleccione el formato del reporte:\n\n")

	for i, format := range m.formats {
		marker := "[ ]"
		style := normalStyle
		if format.Selected {
			marker = "[X]"
			style = selectedStyle
		}
		if i == m.cursor {
			style = focusedStyle
		}

		sb.WriteString(style.Render(fmt.Sprintf("%s %s", marker, format.Name)))
		sb.WriteString("\n")
		sb.WriteString(style.Render(fmt.Sprintf("    %s", format.Description)))
		sb.WriteString("\n\n")
	}

	return sb.String()
}

// renderConfirmStep renderiza el paso de confirmación
func (m Model) renderConfirmStep() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("PASO 6: CONFIRMACIÓN"))
	sb.WriteString("\n\n")

	// Mostrar resumen de configuración
	protocol := "https://"
	if !m.useHTTPS {
		protocol = "http://"
	}

	sb.WriteString("📋 Resumen de configuración:\n\n")
	sb.WriteString(fmt.Sprintf("🌐 URL objetivo: %s%s\n", protocol, m.url))

	// Mostrar perfil seleccionado
	selectedProfile := ""
	for _, profile := range m.profiles {
		if profile.Selected {
			selectedProfile = profile.Name
			break
		}
	}
	if selectedProfile != "" {
		sb.WriteString(fmt.Sprintf("⚙️  Perfil: %s\n", selectedProfile))
	}

	// Contar tests seleccionados
	selectedCount := 0
	for _, test := range m.tests {
		if test.Selected {
			selectedCount++
		}
	}
	sb.WriteString(fmt.Sprintf("🎯 Tests seleccionados: %d\n", selectedCount))

	// Mostrar formato seleccionado
	selectedFormat := ""
	for _, format := range m.formats {
		if format.Selected {
			selectedFormat = format.Name
			break
		}
	}
	if selectedFormat != "" {
		sb.WriteString(fmt.Sprintf("📄 Formato de reporte: %s\n", strings.ToUpper(selectedFormat)))
	}

	sb.WriteString("\n")
	sb.WriteString(successStyle.Render("✅ Presione Enter para iniciar el escaneo"))
	sb.WriteString("\n")
	sb.WriteString(normalStyle.Render("   o Escape para volver atrás"))

	return sb.String()
}

// renderScanningStep renderiza el paso de escaneo
func (m Model) renderScanningStep() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("ESCANEANDO..."))
	sb.WriteString("\n\n")

	// Mostrar URL objetivo
	protocol := "https://"
	if !m.useHTTPS {
		protocol = "http://"
	}
	sb.WriteString(fmt.Sprintf("🎯 Objetivo: %s%s\n", protocol, m.url))

	// Mostrar perfil usado
	selectedProfile := ""
	for _, profile := range m.profiles {
		if profile.Selected {
			selectedProfile = profile.Name
			break
		}
	}
	if selectedProfile != "" {
		sb.WriteString(fmt.Sprintf("⚙️  Perfil: %s\n", selectedProfile))
	}

	sb.WriteString("\n")

	// Mostrar progreso si está disponible
	if m.scanProgress.Total > 0 {
		percent := float64(m.scanProgress.Completed) / float64(m.scanProgress.Total) * 100
		sb.WriteString(fmt.Sprintf("📈 Progreso: %.1f%% [%d/%d]\n",
			percent, m.scanProgress.Completed, m.scanProgress.Total))

		// Barra de progreso visual simple
		progressBarWidth := 40
		filledWidth := int(percent / 100 * float64(progressBarWidth))
		emptyWidth := progressBarWidth - filledWidth

		progressBar := strings.Repeat("█", filledWidth) + strings.Repeat("░", emptyWidth)
		sb.WriteString(fmt.Sprintf("[%s] %.1f%%\n", progressBar, percent))
		sb.WriteString("\n")
	}

	// Mostrar estado actual
	if m.scanProgress.CurrentTest != "" {
		sb.WriteString(fmt.Sprintf("🔍 Ejecutando: %s\n", m.scanProgress.CurrentTest))
	}

	// Mostrar tiempo transcurrido
	elapsed := time.Since(m.scanProgress.StartTime)
	sb.WriteString(fmt.Sprintf("⏱️  Tiempo transcurrido: %s\n", elapsed.Round(time.Second)))

	// Información de progreso
	if m.scanProgress.Completed > 0 {
		sb.WriteString(fmt.Sprintf("✅ Tests completados: %d\n", m.scanProgress.Completed))
	}

	sb.WriteString("\n")
	sb.WriteString(warningStyle.Render("⚠️  Presione 'q' o Ctrl+C para cancelar"))

	return sb.String()
}

// renderFinishingStep renderiza el paso de finalización
func (m Model) renderFinishingStep() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("FINALIZANDO ESCANEO..."))
	sb.WriteString("\n\n")

	sb.WriteString("🔄 Generando reporte...\n")
	sb.WriteString("📊 Calculando puntuación de seguridad...\n")
	sb.WriteString("💾 Guardando resultados...\n\n")

	sb.WriteString(normalStyle.Render("Por favor espere..."))

	return sb.String()
}

// renderResultsStep renderiza los resultados del escaneo con scroll mejorado
func (m Model) renderResultsStep() string {
	var sb strings.Builder

	if m.scanResult == nil {
		sb.WriteString(errorStyle.Render("❌ No hay resultados disponibles"))
		return sb.String()
	}

	// Header de resultados
	sb.WriteString(titleStyle.Render("RESULTADOS DEL ESCANEO"))
	sb.WriteString("\n\n")

	// Información básica
	protocol := "https://"
	if !m.useHTTPS {
		protocol = "http://"
	}
	sb.WriteString(fmt.Sprintf("🎯 Objetivo: %s%s\n", protocol, m.url))

	// Mostrar perfil usado
	selectedProfile := ""
	for _, profile := range m.profiles {
		if profile.Selected {
			selectedProfile = profile.Name
			break
		}
	}
	if selectedProfile != "" {
		sb.WriteString(fmt.Sprintf("⚙️  Perfil usado: %s\n", selectedProfile))
	}

	sb.WriteString(fmt.Sprintf("📅 Fecha: %s\n", m.scanResult.ScanDate.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("⏱️  Duración: %s\n", m.scanResult.Duration))

	// Resumen de vulnerabilidades
	sb.WriteString(fmt.Sprintf("🔍 Tests ejecutados: %d\n", m.scanResult.TestsExecuted))

	sb.WriteString(fmt.Sprintf("🚨 Tests fallidos: %s | Tests pasados: %s\n",
		errorStyle.Render(fmt.Sprintf("%d", m.scanResult.TestsFailed)),
		successStyle.Render(fmt.Sprintf("%d", m.scanResult.TestsPassed))))

	sb.WriteString("\n")

	// Contenido con scroll mejorado
	content := m.renderScrollableResults()

	// Calcular dimensiones para scroll
	lines := strings.Split(content, "\n")
	totalLines := len(lines)
	availableHeight := m.height - 20 // Reservar espacio para header y footer

	if availableHeight < 5 {
		availableHeight = 5
	}

	startLine := m.scrollOffset
	endLine := startLine + availableHeight

	if endLine > totalLines {
		endLine = totalLines
	}

	if startLine >= totalLines {
		startLine = totalLines - 1
		if startLine < 0 {
			startLine = 0
		}
		m.scrollOffset = startLine
	}

	// Mostrar líneas visibles
	visibleLines := lines[startLine:endLine]
	scrollContent := strings.Join(visibleLines, "\n")

	// Agregar indicadores de scroll visuales e intuitivos
	if totalLines > availableHeight {
		// Indicadores llamativos arriba y abajo
		if m.scrollOffset > 0 {
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
		scrollContent += fmt.Sprintf("\n🎮 ↑↓ Línea | PgUp/PgDn Página | Home/End Inicio/Final")
	}

	sb.WriteString(scrollContent)

	return sb.String()
}

// renderScrollableResults genera el contenido completo de resultados para scroll
func (m Model) renderScrollableResults() string {
	var sb strings.Builder

	if len(m.scanResult.TestResults) == 0 {
		sb.WriteString("✅ No se encontraron vulnerabilidades.\n")
		return sb.String()
	}

	// Mostrar resultados por test
	failedResults := []tests.TestResult{}
	passedResults := []tests.TestResult{}

	for _, result := range m.scanResult.TestResults {
		if result.Status == "Failed" {
			failedResults = append(failedResults, result)
		} else {
			passedResults = append(passedResults, result)
		}
	}

	// Mostrar tests fallidos primero
	if len(failedResults) > 0 {
		sb.WriteString(errorStyle.Render("🚨 TESTS FALLIDOS"))
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

	// Mostrar tests pasados
	if len(passedResults) > 0 {
		sb.WriteString(successStyle.Render("✅ TESTS PASADOS"))
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
	sb.WriteString(successStyle.Render("📊 RESUMEN DE SEGURIDAD"))
	sb.WriteString("\n\n")

	if len(failedResults) > 0 {
		sb.WriteString("🚨 CRÍTICO: Se encontraron vulnerabilidades que deben ser resueltas.\n")
	} else {
		sb.WriteString("✅ EXCELENTE: No se encontraron vulnerabilidades críticas.\n")
	}

	sb.WriteString(fmt.Sprintf("\n📄 Reporte completo guardado en: reports/\n"))
	sb.WriteString(fmt.Sprintf("📈 Puntuación de seguridad: %.1f/10\n", m.scanResult.SecurityScore.Value))

	return sb.String()
}

// renderFooter renderiza el footer con ayuda contextual
func (m Model) renderFooter() string {
	var help strings.Builder

	switch m.state {
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
		help.WriteString("🎮 ↑↓: Scroll línea | PgUp/PgDn: Scroll página | Home/End: Inicio/Final | Enter: Nuevo escaneo | Esc: Salir")
	default:
		help.WriteString("🎮 Navegación con ↑↓ | Enter: Seleccionar | Esc: Volver/Salir")
	}

	return normalStyle.Render(help.String())
}

// renderModal renderiza un modal centrado
func (m Model) renderModal(content string) string {
	modal := modalStyle.Render(content)

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
	topPadding := (m.height - modalHeight) / 2
	if topPadding < 0 {
		topPadding = 0
	}

	leftPadding := (m.width - modalWidth) / 2
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
		result.WriteString(strings.Repeat(" ", leftPadding))
		result.WriteString(line)
		result.WriteString("\n")
	}

	return result.String()
}
