package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
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

	title := headerStyle.Render("🔐 VersaSecurityTest - Interactive Web Security Scanner v2.0")
	
	return banner + "\n\n" + title
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
	
	sb.WriteString(titleStyle.Render("PASO 2: INGRESO DE URL"))
	sb.WriteString("\n\n")
	
	protocol := "https://"
	if !m.useHTTPS {
		protocol = "http://"
	}
	
	sb.WriteString(fmt.Sprintf("Protocolo seleccionado: %s\n\n", successStyle.Render(protocol)))
	sb.WriteString("Ingrese la URL objetivo (sin protocolo):\n")
	sb.WriteString("Ejemplos: localhost:8080, www.ejemplo.com, api.ejemplo.com/v1\n\n")
	
	// Campo de entrada
	urlField := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#7D56F4")).
		Padding(0, 1).
		Width(50)
	
	fullURL := protocol + m.url
	if m.url == "" {
		fullURL = protocol + "▋" // Cursor
	} else {
		fullURL += "▋" // Cursor al final
	}
	
	sb.WriteString(urlField.Render(fullURL))
	sb.WriteString("\n\n")
	
	if m.url != "" {
		sb.WriteString(fmt.Sprintf("URL completa: %s\n", successStyle.Render(protocol+m.url)))
	}
	
	return sb.String()
}

// renderTestsStep renderiza el paso de selección de tests
func (m Model) renderTestsStep() string {
	var sb strings.Builder
	
	sb.WriteString(titleStyle.Render("PASO 3: SELECCIÓN DE TESTS"))
	sb.WriteString("\n\n")
	
	selectedCount := 0
	for _, test := range m.tests {
		if test.Selected {
			selectedCount++
		}
	}
	
	sb.WriteString(fmt.Sprintf("Tests seleccionados: %s\n\n", 
		successStyle.Render(fmt.Sprintf("%d/%d", selectedCount, len(m.tests)))))
	
	// Renderizar tests en dos columnas
	colWidth := (m.width - 10) / 2
	if colWidth < 30 {
		colWidth = 30
	}
	
	leftCol := strings.Builder{}
	rightCol := strings.Builder{}
	
	halfTests := (len(m.tests) + 1) / 2
	
	for i, test := range m.tests {
		var col *strings.Builder
			// adjustedCursor := m.cursor // No se usa en esta implementación
		
		if i < halfTests {
			col = &leftCol
		} else {
			col = &rightCol
			// adjustedCursor = m.cursor - halfTests // No se usa
		}
		
		// Checkbox
		checkbox := "[ ]"
		if test.Selected {
			checkbox = "[X]"
		}
		
		// Estilo
		style := normalStyle
		if (i < halfTests && m.cursor == i) || (i >= halfTests && m.cursor == i) {
			style = focusedStyle
		} else if test.Selected {
			style = selectedStyle
		}
		
		// Indicador de recomendado
		recommended := ""
		if test.Recommended {
			recommended = " ⭐"
		}
		
		// Formatear línea
		line := fmt.Sprintf("%s %s%s", checkbox, test.Name, recommended)
		col.WriteString(style.Render(line))
		col.WriteString("\n")
		
		// Descripción (solo si está seleccionado con cursor)
		if (i < halfTests && m.cursor == i) || (i >= halfTests && m.cursor == i) {
			desc := fmt.Sprintf("   📝 %s", test.Description)
			if len(desc) > colWidth-3 {
				desc = desc[:colWidth-6] + "..."
			}
			col.WriteString(warningStyle.Render(desc))
			col.WriteString("\n")
		}
		col.WriteString("\n")
	}
	
	// Combinar columnas
	leftLines := strings.Split(strings.TrimRight(leftCol.String(), "\n"), "\n")
	rightLines := strings.Split(strings.TrimRight(rightCol.String(), "\n"), "\n")
	
	maxLines := len(leftLines)
	if len(rightLines) > maxLines {
		maxLines = len(rightLines)
	}
	
	for i := 0; i < maxLines; i++ {
		leftLine := ""
		rightLine := ""
		
		if i < len(leftLines) {
			leftLine = leftLines[i]
		}
		if i < len(rightLines) {
			rightLine = rightLines[i]
		}
		
		// Asegurar ancho de columna izquierda
		leftPadded := leftLine + strings.Repeat(" ", colWidth-lipgloss.Width(leftLine))
		if lipgloss.Width(leftLine) > colWidth {
			leftPadded = leftLine[:colWidth-3] + "..."
		}
		
		sb.WriteString(leftPadded + "  " + rightLine)
		sb.WriteString("\n")
	}
	
	sb.WriteString("\n")
	sb.WriteString("💡 Atajos: [A]ll | [N]one | [R]ecommended | ⭐ = Recomendado\n")
	
	return sb.String()
}

// renderFormatStep renderiza el paso de selección de formato
func (m Model) renderFormatStep() string {
	var sb strings.Builder
	
	sb.WriteString(titleStyle.Render("PASO 4: FORMATO DE SALIDA"))
	sb.WriteString("\n\n")
	
	for i, format := range m.formats {
		checkbox := "[ ]"
		if format.Selected {
			checkbox = "[X]"
		}
		
		style := normalStyle
		if m.cursor == i {
			style = focusedStyle
		} else if format.Selected {
			style = selectedStyle
		}
		
		line := fmt.Sprintf("%s %s", checkbox, format.Name)
		sb.WriteString(style.Render(line))
		sb.WriteString("\n")
		
		if m.cursor == i {
			desc := fmt.Sprintf("   📝 %s", format.Description)
			sb.WriteString(warningStyle.Render(desc))
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}
	
	// Configuraciones adicionales
	sb.WriteString(titleStyle.Render("CONFIGURACIONES ADICIONALES"))
	sb.WriteString("\n\n")
	
	verboseCheckbox := "[ ]"
	if m.verbose {
		verboseCheckbox = "[X]"
	}
	verboseStyle := normalStyle
	if m.verbose {
		verboseStyle = selectedStyle
	}
	sb.WriteString(verboseStyle.Render(fmt.Sprintf("%s Modo Verbose (mostrar detalles adicionales)", verboseCheckbox)))
	sb.WriteString("\n\n")
	
	sb.WriteString("💡 Presione [V] para activar/desactivar el modo verbose en cualquier momento\n")
	
	return sb.String()
}

// renderConfirmStep renderiza el paso de confirmación
func (m Model) renderConfirmStep() string {
	var sb strings.Builder
	
	sb.WriteString(titleStyle.Render("PASO 5: CONFIRMACIÓN"))
	sb.WriteString("\n\n")
	
	// Resumen de configuración
	protocol := "https://"
	if !m.useHTTPS {
		protocol = "http://"
	}
	
	sb.WriteString("📋 RESUMEN DE CONFIGURACIÓN:\n")
	sb.WriteString(strings.Repeat("─", 50) + "\n")
	sb.WriteString(fmt.Sprintf("🎯 URL Objetivo:     %s\n", successStyle.Render(protocol+m.url)))
	
	selectedTests := []string{}
	for _, test := range m.tests {
		if test.Selected {
			selectedTests = append(selectedTests, test.Name)
		}
	}
	sb.WriteString(fmt.Sprintf("🔍 Tests (%d):        %s\n", len(selectedTests), strings.Join(selectedTests[:min(3, len(selectedTests))], ", ")))
	if len(selectedTests) > 3 {
		sb.WriteString(fmt.Sprintf("                     ... y %d más\n", len(selectedTests)-3))
	}
	
	selectedFormat := ""
	for _, format := range m.formats {
		if format.Selected {
			selectedFormat = format.Name
			break
		}
	}
	sb.WriteString(fmt.Sprintf("📊 Formato:          %s\n", selectedFormat))
	sb.WriteString(fmt.Sprintf("🔍 Modo Verbose:     %v\n", m.verbose))
	sb.WriteString(strings.Repeat("─", 50) + "\n\n")
	
	// Opciones de confirmación
	confirmStyle := normalStyle
	cancelStyle := normalStyle
	
	if m.cursor == 0 {
		confirmStyle = focusedStyle
	} else {
		cancelStyle = focusedStyle
	}
	
	sb.WriteString("¿Desea proceder con el escaneo?\n\n")
	sb.WriteString(confirmStyle.Render("[ ] ✅ Confirmar y ejecutar escaneo"))
	sb.WriteString("\n")
	sb.WriteString(cancelStyle.Render("[ ] ❌ Cancelar y volver atrás"))
	sb.WriteString("\n")
	
	return sb.String()
}

// renderScanningStep renderiza el paso de escaneo en progreso
func (m Model) renderScanningStep() string {
	var sb strings.Builder
	
	sb.WriteString(titleStyle.Render("🚀 ESCANEO EN PROGRESO"))
	sb.WriteString("\n\n")
	
	protocol := "https://"
	if !m.useHTTPS {
		protocol = "http://"
	}
	
	sb.WriteString(fmt.Sprintf("🎯 Escaneando: %s\n\n", successStyle.Render(protocol+m.url)))
	
	// Barra de progreso
	if m.scanProgress.Total > 0 {
		progress := float64(m.scanProgress.Completed) / float64(m.scanProgress.Total)
		barWidth := 50
		filled := int(progress * float64(barWidth))
		
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
		sb.WriteString(fmt.Sprintf("Progreso: [%s] %.1f%%\n", bar, progress*100))
		sb.WriteString(fmt.Sprintf("Tests completados: %d/%d\n\n", m.scanProgress.Completed, m.scanProgress.Total))
	}
	
	// Test actual con tiempo
	if m.scanProgress.CurrentTest != "" {
		sb.WriteString(fmt.Sprintf("🔍 Test actual: %s\n", warningStyle.Render(m.scanProgress.CurrentTest)))
		if m.scanProgress.CurrentTestTime > 0 {
			sb.WriteString(fmt.Sprintf("⏱️  Tiempo del test: %v\n", m.scanProgress.CurrentTestTime.Round(time.Millisecond)))
		}
	}
	
	// Tiempo total transcurrido
	if m.scanProgress.Duration > 0 {
		sb.WriteString(fmt.Sprintf("⏱️  Tiempo total: %v\n", m.scanProgress.Duration.Round(time.Second)))
	}
	
	// Detalles de tests si está en modo verbose
	if m.verbose && len(m.scanProgress.TestDetails) > 0 {
		sb.WriteString("\n📋 DETALLES DE TESTS:\n")
		sb.WriteString(strings.Repeat("─", 40) + "\n")
		
		for _, test := range m.scanProgress.TestDetails {
			statusIcon := "⏳"
			statusStyle := normalStyle
			
			switch test.Status {
			case "completed":
				statusIcon = "✅"
				statusStyle = successStyle
			case "failed":
				statusIcon = "❌"
				statusStyle = errorStyle
			case "running":
				statusIcon = "🔄"
				statusStyle = warningStyle
			case "pending":
				statusIcon = "⏳"
				statusStyle = normalStyle
			}
			
			line := fmt.Sprintf("%s %s", statusIcon, test.Name)
			if test.Duration > 0 {
				line += fmt.Sprintf(" (%v)", test.Duration.Round(time.Millisecond))
			}
			
			sb.WriteString(statusStyle.Render(line))
			sb.WriteString("\n")
			
			if test.Message != "" {
				sb.WriteString(fmt.Sprintf("   📝 %s\n", normalStyle.Render(test.Message)))
			}
		}
	}
	
	sb.WriteString("\n💡 Controles: [Q] Cancelar | [V] Toggle Verbose | [D] Detalles\n")
	
	return sb.String()
}

// renderResultsStep renderiza el paso de resultados
func (m Model) renderResultsStep() string {
	var sb strings.Builder
	
	sb.WriteString(titleStyle.Render("📊 RESULTADOS DEL ESCANEO"))
	sb.WriteString("\n\n")
	
	if m.scanResult == nil {
		sb.WriteString(errorStyle.Render("No hay resultados disponibles"))
		return sb.String()
	}
	
	// Resumen principal
	sb.WriteString("📋 RESUMEN EJECUTIVO:\n")
	sb.WriteString(strings.Repeat("═", 60) + "\n")
	
	protocol := "https://"
	if !m.useHTTPS {
		protocol = "http://"
	}
	
	sb.WriteString(fmt.Sprintf("🎯 URL Escaneada:    %s\n", protocol+m.url))
	sb.WriteString(fmt.Sprintf("📅 Fecha/Hora:       %s\n", m.scanResult.ScanDate.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("⏱️  Duración:         %v\n", m.scanResult.Duration.Round(time.Millisecond)))
	sb.WriteString(fmt.Sprintf("🔍 Tests Ejecutados: %d\n", m.scanResult.TestsExecuted))
	sb.WriteString(fmt.Sprintf("✅ Tests Pasados:    %s\n", successStyle.Render(fmt.Sprintf("%d", m.scanResult.TestsPassed))))
	sb.WriteString(fmt.Sprintf("❌ Tests Fallidos:   %s\n", errorStyle.Render(fmt.Sprintf("%d", m.scanResult.TestsFailed))))
	sb.WriteString(strings.Repeat("═", 60) + "\n\n")
	
	// Puntuación de seguridad
	score := m.scanResult.SecurityScore.Value
	risk := m.scanResult.SecurityScore.Risk
	
	scoreStyle := successStyle
	if score < 7.0 {
		scoreStyle = warningStyle
	}
	if score < 4.0 {
		scoreStyle = errorStyle
	}
	
	sb.WriteString("🛡️  PUNTUACIÓN DE SEGURIDAD:\n")
	sb.WriteString(strings.Repeat("─", 30) + "\n")
	sb.WriteString(fmt.Sprintf("Puntuación: %s/10\n", scoreStyle.Render(fmt.Sprintf("%.1f", score))))
	sb.WriteString(fmt.Sprintf("Nivel de Riesgo: %s\n\n", scoreStyle.Render(risk)))
	
	// Resultados resumidos por categoría
	if len(m.scanResult.TestResults) > 0 {
		sb.WriteString("📝 RESULTADOS POR TEST:\n")
		sb.WriteString(strings.Repeat("─", 40) + "\n")
		
		for _, result := range m.scanResult.TestResults {
			status := errorStyle.Render("❌ FALLÓ")
			if result.Status == "Passed" {
				status = successStyle.Render("✅ PASÓ")
			}
			
			sb.WriteString(fmt.Sprintf("%s %s\n", status, result.TestName))
			if result.Description != "" && result.Status != "Passed" {
				sb.WriteString(fmt.Sprintf("    %s\n", warningStyle.Render(result.Description)))
			}
			
			// Agregar detalle adicional cuando el test falla
			if result.Status == "Failed" && len(result.Evidence) > 0 {
				sb.WriteString("    🔴 Detalles del fallo:\n")
				
				// Mostrar la primera evidencia como ejemplo
				evidence := result.Evidence[0]
				sb.WriteString(fmt.Sprintf("      📝 Tipo: %s\n", errorStyle.Render(evidence.Type)))
				sb.WriteString(fmt.Sprintf("      💬 Payload: %s\n", warningStyle.Render(evidence.Payload)))
				sb.WriteString(fmt.Sprintf("      📞 Respuesta: %s\n", normalStyle.Render(evidence.Response)))
				
				if len(result.Evidence) > 1 {
					sb.WriteString(fmt.Sprintf("      ℹ️  ... y %d evidencias más (ver detalles completos)\n", len(result.Evidence)-1))
				}
				sb.WriteString("\n")
			} else if result.Status == "Failed" {
				// Fallback si no hay evidencias específicas
				sb.WriteString("    🔴 Ejemplos de lo que se detectó:\n")
				switch result.TestName {
				case "SQL Injection":
					sb.WriteString(fmt.Sprintf("      💬 Payload usado: %s\n", warningStyle.Render("' OR '1'='1")))
					sb.WriteString(fmt.Sprintf("      📞 Respuesta: %s\n", errorStyle.Render("Error SQL o comportamiento anormal")))
				case "Cross-Site Scripting":
					sb.WriteString(fmt.Sprintf("      💬 Payload usado: %s\n", warningStyle.Render("<script>alert('XSS')</script>")))
					sb.WriteString(fmt.Sprintf("      📞 Respuesta: %s\n", errorStyle.Render("Script reflejado sin sanitización")))
				case "Headers de Seguridad":
					sb.WriteString(fmt.Sprintf("      💬 Header faltante: %s\n", warningStyle.Render("X-Frame-Options")))
					sb.WriteString(fmt.Sprintf("      📞 Riesgo: %s\n", errorStyle.Render("Posible clickjacking")))
				default:
					sb.WriteString(fmt.Sprintf("      📞 Resultado: %s\n", errorStyle.Render("Vulnerabilidad detectada")))
				}
				sb.WriteString("\n")
			}
		}
		sb.WriteString("\n")
	}
	// Recomendaciones principales
	if len(m.scanResult.Recommendations) > 0 {
		sb.WriteString("💡 RECOMENDACIONES PRINCIPALES:\n")
		sb.WriteString(strings.Repeat("─", 40) + "\n")
		maxRecs := min(5, len(m.scanResult.Recommendations))
		for i := 0; i < maxRecs; i++ {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, m.scanResult.Recommendations[i]))
		}
		if len(m.scanResult.Recommendations) > 5 {
			sb.WriteString(fmt.Sprintf("   ... y %d recomendaciones más (ver detalles)\n", len(m.scanResult.Recommendations)-5))
		}
		sb.WriteString("\n")
	}
	
	sb.WriteString("🎮 OPCIONES:\n")
	sb.WriteString("   [D/Enter] Ver detalles completos\n")
	sb.WriteString("   [R] Repetir escaneo\n")
	sb.WriteString("   [S] Guardar reporte\n")
	sb.WriteString("   [Backspace] Nuevo escaneo\n")
	sb.WriteString("   [Q/Esc] Salir\n")
	
	return sb.String()
}

// renderFooter renderiza el footer con ayuda
func (m Model) renderFooter() string {
	var help strings.Builder
	
	help.WriteString("🎮 CONTROLES: ")
	
	switch m.state {
	case StateProtocol:
		help.WriteString("↑↓ Navegar | Space Seleccionar | Enter Continuar | Q Salir")
	case StateURL:
		help.WriteString("Escribir URL | Enter Continuar | Esc Volver | Q Salir")
	case StateTests:
		help.WriteString("↑↓←→ Navegar | Space Seleccionar | A Todos | N Ninguno | R Recomendados | Enter Continuar")
	case StateFormat:
		help.WriteString("↑↓ Navegar | Space Seleccionar | V Verbose | Enter Continuar")
	case StateConfirm:
		help.WriteString("↑↓ Navegar | Space Seleccionar | Enter Confirmar | Esc Volver")
	case StateScanning:
		help.WriteString("Q Cancelar escaneo")
	case StateResults:
		help.WriteString("D Detalles | R Repetir | S Guardar | Backspace Nuevo | Q Salir")
	}
	
	if m.verbose {
		help.WriteString(" | 🔍 VERBOSE ACTIVO")
	}
	
	footerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#888888")).
		Background(lipgloss.Color("#1a1a1a")).
		Padding(0, 1)
	
	return footerStyle.Render(help.String())
}

// renderModal renderiza un modal sobre el contenido principal
func (m Model) renderModal(content string) string {
	// Crear el contenido del modal
	modalWidth := min(m.width-10, 100)
	modalHeight := min(m.height-10, 30)
	
	// Procesar el contenido para que quepa en el modal
	lines := strings.Split(m.modalContent, "\n")
	modalLines := []string{}
	
	for _, line := range lines {
		if len(line) <= modalWidth-4 {
			modalLines = append(modalLines, line)
		} else {
			// Partir líneas largas
			for len(line) > modalWidth-4 {
				modalLines = append(modalLines, line[:modalWidth-4])
				line = line[modalWidth-4:]
			}
			if len(line) > 0 {
				modalLines = append(modalLines, line)
			}
		}
		
		if len(modalLines) >= modalHeight-4 {
			modalLines = append(modalLines, "... (contenido truncado)")
			break
		}
	}
	
	modalContent := strings.Join(modalLines, "\n")
	
	// Crear el modal
	modal := modalStyle.
		Width(modalWidth).
		Height(modalHeight).
		Render(fmt.Sprintf("%s\n\n%s\n\n%s", 
			titleStyle.Render(m.modalTitle),
			modalContent,
			normalStyle.Render("Presione ESC o Q para cerrar")))
	
	// Posicionar el modal en el centro
	_ = (m.width - modalWidth) / 2  // modalX no se usa
	_ = (m.height - modalHeight) / 2 // modalY no se usa
	
	// Crear el overlay
	overlay := lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
	
	return overlay
}

// min retorna el menor de dos enteros
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
