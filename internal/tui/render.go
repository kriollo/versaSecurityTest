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

	head // Agregar indicadores de scro	// Agregar indicadores de scroll visuales e intuitivos
	scrollContent := strings.Join(visibleLines, "\n")
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

// renderURLStep renderiza el paso de entrada de URL
		}
		progressBar += "]"

		// Información de navegación detallada con estilo
		scrollContent += fmt.Sprintf("\n\n📜 NAVEGACIÓN DE RESULTADOS:")
		scrollContent += fmt.Sprintf("\n   %s %.1f%% - Mostrando líneas %d-%d de %d total",
			progressBar, float64(endLine)/float64(totalLines)*100, startLine+1, endLine, totalLines)
		scrollContent += fmt.Sprintf("\n   🎮 ↑↓ Scroll línea por línea | PgUp/PgDn Scroll página completa | Home/End Ir al inicio/final")

		// Indicador de posición específico
		if m.scrollOffset == 0 {
			scrollContent += "\n   📍 Estás viendo el INICIO del reporte"
		} else if endLine >= totalLines {
			scrollContent += "\n   📍 Estás viendo el FINAL del reporte"
		} else {
			scrollContent += fmt.Sprintf("\n   📍 Posición actual: %.1f%% del reporte completo", float64(startLine+availableHeight/2)/float64(totalLines)*100)
		}
	}

	sb.WriteString(scrollContent)
	return sb.String()
}

// renderURLStep renderiza el paso de entrada de URL
func (m Model) renderURLStep() string {
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

// renderProfileStep renderiza el paso de selección de perfil de escaneo
func (m Model) renderProfileStep() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("PASO 3: SELECCIÓN DE PERFIL DE ESCANEO"))
	sb.WriteString("\n\n")

	protocol := "https://"
	if !m.useHTTPS {
		protocol = "http://"
	}

	sb.WriteString(fmt.Sprintf("🎯 URL objetivo: %s\n\n", successStyle.Render(protocol+m.url)))

	sb.WriteString("Seleccione el nivel de escaneo que desea realizar:\n\n")

	// Renderizar cada perfil
	for i, profile := range m.profiles {
		var style lipgloss.Style
		var marker string
		var prefix string

		if profile.Selected {
			marker = "[X]"
			style = focusedStyle
		} else {
			marker = "[ ]"
			style = normalStyle
		}

		if i == m.cursor {
			prefix = "→"
			style = style.Bold(true)
		} else {
			prefix = " "
		}

		// Formatear timeout
		timeoutStr := fmt.Sprintf("%.0fs", profile.Timeout.Seconds())

		sb.WriteString(style.Render(fmt.Sprintf("%s%s %s", prefix, marker, profile.Name)))
		sb.WriteString("\n")
		sb.WriteString(style.Render(fmt.Sprintf("     %s", profile.Description)))
		sb.WriteString("\n")
		sb.WriteString(style.Render(fmt.Sprintf("     📊 %d tests | ⏱️ %s | 🧵 %d hilos",
			profile.TestCount, timeoutStr, profile.Concurrent)))
		sb.WriteString("\n\n")
	}

	sb.WriteString("\n")
	sb.WriteString("💡 NAVEGACIÓN: [↑↓] Perfil anterior/siguiente | [SPACE] Seleccionar | [Enter] Continuar\n")
	sb.WriteString("\n")
	sb.WriteString("🎮 CONTROLES: ↑↓ Navegar | Space Seleccionar | Enter Continuar | Esc Volver")

	return sb.String()
}

// renderTestsStep renderiza el paso de selección de tests en columnas compactas
func (m Model) renderTestsStep() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("PASO 3: SELECCIÓN DE TESTS DE SEGURIDAD OWASP"))
	sb.WriteString("\n\n")

	selectedCount := 0
	recommendedCount := 0
	for _, test := range m.tests {
		if test.Selected {
			selectedCount++
		}
		if test.Recommended {
			recommendedCount++
		}
	}

	url := "https://"
	if !m.useHTTPS {
		url = "http://"
	}
	url += m.url

	sb.WriteString(fmt.Sprintf("🎯 URL objetivo: %s\n", successStyle.Render(url)))
	sb.WriteString(fmt.Sprintf("📊 Tests seleccionados: %s | Recomendados: %d\n\n",
		successStyle.Render(fmt.Sprintf("%d/%d", selectedCount, len(m.tests))), recommendedCount))

	// Renderizar tests en columnas compactas
	sb.WriteString(m.renderTestsInColumns())

	// Mostrar descripción del test enfocado
	if m.cursor >= 0 && m.cursor < len(m.tests) {
		focusedTest := m.tests[m.cursor]
		sb.WriteString("\n")
		sb.WriteString(warningStyle.Render("─────────────────────────────────────────────────────────────────────"))
		sb.WriteString("\n")
		sb.WriteString(warningStyle.Render(fmt.Sprintf("📋 %s", focusedTest.Description)))
		sb.WriteString("\n")
		sb.WriteString(warningStyle.Render(fmt.Sprintf("🏷️ Categoría: %s (%s)", focusedTest.Category, getCategoryDescription(focusedTest.Category))))
		sb.WriteString("\n")
		sb.WriteString(warningStyle.Render("─────────────────────────────────────────────────────────────────────"))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	if m.verbose {
		sb.WriteString("🔍 Modo verbose: " + successStyle.Render("ACTIVADO") + " (mostrará detalles completos)\n")
	} else {
		sb.WriteString("🔍 Modo verbose: DESACTIVADO (presione 'v' para activar)\n")
	}

	if m.useAdvancedTests {
		sb.WriteString("🚀 Tests avanzados: " + successStyle.Render("ACTIVADOS") + " (técnicas agresivas y evasión)\n")
	} else {
		sb.WriteString("� Tests avanzados: DESACTIVADOS (presione 'x' para activar)\n")
	}

	sb.WriteString("�� Atajos: [SPACE] Seleccionar | [A] Todos | [N] Ninguno | [R] Recomendados | [V] Verbose | [X] Avanzados\n")
	sb.WriteString("   ⭐ = Recomendado | ☑ = Seleccionado | → = Cursor actual\n")

	return sb.String()
}

// getCategoryDescription devuelve una descripción breve de la categoría OWASP
func getCategoryDescription(category string) string {
	descriptions := map[string]string{
		"INFO": "Recolección de Info",
		"CONF": "Configuración",
		"IDNT": "Identidad",
		"ATHN": "Autenticación",
		"ATHZ": "Autorización",
		"SESS": "Sesiones",
		"INPV": "Validación Entrada",
		"ERRH": "Manejo Errores",
		"CRYP": "Criptografía",
		"BUSL": "Lógica Negocio",
		"CLNT": "Cliente",
		"APIT": "APIs",
		"MISC": "Adicionales",
	}

	if desc, exists := descriptions[category]; exists {
		return desc
	}
	return "Otros"
}

// getGlobalTestIndex encuentra el índice global de un test por su ID
func getGlobalTestIndex(tests []TestItem, id string) int {
	for i, test := range tests {
		if test.ID == id {
			return i
		}
	}
	return -1
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

	sb.WriteString(titleStyle.Render("🔍 ESCANEO EN PROGRESO"))
	sb.WriteString("\n\n")

	// Mostrar información del objetivo
	protocol := "https://"
	if !m.useHTTPS {
		protocol = "http://"
	}
	fullURL := protocol + m.url

	sb.WriteString(fmt.Sprintf("🎯 Objetivo: %s\n", successStyle.Render(fullURL)))
	sb.WriteString(fmt.Sprintf("📊 Tests seleccionados: %d\n", countSelectedTests(m.tests)))

	// Mostrar tiempo transcurrido
	elapsed := time.Since(m.scanProgress.StartTime)
	sb.WriteString(fmt.Sprintf("⏱️  Tiempo transcurrido: %s\n", elapsed.Round(time.Second)))
	sb.WriteString("\n")

	// Mostrar progreso si está disponible
	if m.scanProgress.Total > 0 {
		percent := float64(m.scanProgress.Completed) / float64(m.scanProgress.Total) * 100
		sb.WriteString(fmt.Sprintf("📈 Progreso: %.1f%% [%d/%d]\n",
			percent, m.scanProgress.Completed, m.scanProgress.Total))

		// Barra de progreso visual
		progressBarWidth := 50
		filledWidth := int(percent / 100 * float64(progressBarWidth))
		emptyWidth := progressBarWidth - filledWidth

		progressBar := strings.Repeat("█", filledWidth) + strings.Repeat("░", emptyWidth)
		sb.WriteString(fmt.Sprintf("█%s█ %.1f%%\n", progressBar, percent))
		sb.WriteString("\n")

		// Test actual si está disponible
		if m.scanProgress.CurrentTest != "" {
			sb.WriteString(fmt.Sprintf("🔄 Test actual: %s\n", warningStyle.Render(m.scanProgress.CurrentTest)))
		}
	} else {
		// Spinner de carga si no hay progreso específico
		spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		spinner := spinners[int(elapsed.Seconds())%len(spinners)]
		sb.WriteString(fmt.Sprintf("%s Ejecutando tests de seguridad...\n", spinner))
	}

	sb.WriteString("\n")
	sb.WriteString(warningStyle.Render("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	sb.WriteString("\n")
	sb.WriteString("💡 CONTROLES DURANTE EL ESCANEO:\n")
	sb.WriteString("   • Presiona 'S' para saltar el test actual\n")
	sb.WriteString("   • Presiona 'Q' o 'Esc' para cancelar el escaneo\n")
	sb.WriteString("   • Presiona 'V' para activar/desactivar modo verbose\n")
	sb.WriteString(warningStyle.Render("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	return sb.String()
}

// renderFinishingStep renderiza el paso de finalización
func (m Model) renderFinishingStep() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("⏳ FINALIZANDO ESCANEO"))
	sb.WriteString("\n\n")

	// Spinner de finalización
	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	elapsed := time.Since(m.finishingStart)
	spinner := spinners[int(elapsed.Milliseconds()/100)%len(spinners)]

	sb.WriteString(fmt.Sprintf("%s Generando reporte y calculando puntuación de seguridad...\n", spinner))
	sb.WriteString(fmt.Sprintf("⏱️  Tiempo de procesamiento: %s\n", elapsed.Round(time.Millisecond*100)))

	return sb.String()
}

// renderResultsStep renderiza el paso de resultados con scroll
func (m Model) renderResultsStep() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("📊 RESULTADOS DEL ESCANEO"))
	sb.WriteString("\n\n")

	if m.scanResult == nil {
		sb.WriteString(errorStyle.Render("No hay resultados disponibles"))
		return sb.String()
	}

	// Generar todo el contenido primero
	var fullContent strings.Builder

	// Resumen principal
	fullContent.WriteString("📋 RESUMEN EJECUTIVO:\n")
	fullContent.WriteString(strings.Repeat("═", 60) + "\n")

	protocol := "https://"
	if !m.useHTTPS {
		protocol = "http://"
	}

	fullContent.WriteString(fmt.Sprintf("🎯 URL Escaneada:    %s\n", protocol+m.url))
	fullContent.WriteString(fmt.Sprintf("📅 Fecha/Hora:       %s\n", m.scanResult.ScanDate.Format("2006-01-02 15:04:05")))
	fullContent.WriteString(fmt.Sprintf("⏱️  Duración:         %v\n", m.scanResult.Duration.Round(time.Millisecond)))
	fullContent.WriteString(fmt.Sprintf("🔍 Tests Ejecutados: %d\n", m.scanResult.TestsExecuted))
	fullContent.WriteString(fmt.Sprintf("✅ Tests Pasados:    %s\n", successStyle.Render(fmt.Sprintf("%d", m.scanResult.TestsPassed))))
	fullContent.WriteString(fmt.Sprintf("❌ Tests Fallidos:   %s\n", errorStyle.Render(fmt.Sprintf("%d", m.scanResult.TestsFailed))))
	fullContent.WriteString(strings.Repeat("═", 60) + "\n\n")

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

	fullContent.WriteString("🛡️  PUNTUACIÓN DE SEGURIDAD:\n")
	fullContent.WriteString(strings.Repeat("─", 30) + "\n")
	fullContent.WriteString(fmt.Sprintf("Puntuación: %s/10\n", scoreStyle.Render(fmt.Sprintf("%.1f", score))))
	fullContent.WriteString(fmt.Sprintf("Nivel de Riesgo: %s\n\n", scoreStyle.Render(risk)))

	// Resultados resumidos por categoría
	if len(m.scanResult.TestResults) > 0 {
		fullContent.WriteString("📝 RESULTADOS POR TEST:\n")
		fullContent.WriteString(strings.Repeat("─", 40) + "\n")

		for _, result := range m.scanResult.TestResults {
			status := errorStyle.Render("❌ FALLÓ")
			if result.Status == "Passed" {
				status = successStyle.Render("✅ PASÓ")
			}

			fullContent.WriteString(fmt.Sprintf("%s %s\n", status, result.TestName))
			if result.Description != "" && result.Status != "Passed" {
				fullContent.WriteString(fmt.Sprintf("    %s\n", warningStyle.Render(result.Description)))
			}

			// Agregar detalle adicional cuando el test falla
			if result.Status == "Failed" && len(result.Evidence) > 0 {
				fullContent.WriteString("    🔴 Detalles del fallo:\n")

				// Mostrar la primera evidencia como ejemplo
				evidence := result.Evidence[0]
				fullContent.WriteString(fmt.Sprintf("      📝 Tipo: %s\n", errorStyle.Render(evidence.Type)))
				fullContent.WriteString(fmt.Sprintf("      💬 Payload: %s\n", warningStyle.Render(evidence.Payload)))
				fullContent.WriteString(fmt.Sprintf("      📞 Respuesta: %s\n", normalStyle.Render(evidence.Response)))

				if len(result.Evidence) > 1 {
					fullContent.WriteString(fmt.Sprintf("      ℹ️  ... y %d evidencias más (ver detalles completos)\n", len(result.Evidence)-1))
				}
				fullContent.WriteString("\n")
			} else if result.Status == "Failed" {
				// Fallback si no hay evidencias específicas
				fullContent.WriteString("    🔴 Ejemplos de lo que se detectó:\n")
				switch result.TestName {
				case "SQL Injection":
					fullContent.WriteString(fmt.Sprintf("      💬 Payload usado: %s\n", warningStyle.Render("' OR '1'='1")))
					fullContent.WriteString(fmt.Sprintf("      📞 Respuesta: %s\n", errorStyle.Render("Error SQL o comportamiento anormal")))
				case "Cross-Site Scripting":
					fullContent.WriteString(fmt.Sprintf("      💬 Payload usado: %s\n", warningStyle.Render("<script>alert('XSS')</script>")))
					fullContent.WriteString(fmt.Sprintf("      📞 Respuesta: %s\n", errorStyle.Render("Script reflejado sin sanitización")))
				case "Headers de Seguridad":
					fullContent.WriteString(fmt.Sprintf("      💬 Header faltante: %s\n", warningStyle.Render("X-Frame-Options")))
					fullContent.WriteString(fmt.Sprintf("      📞 Riesgo: %s\n", errorStyle.Render("Posible clickjacking")))
				default:
					fullContent.WriteString(fmt.Sprintf("      📞 Resultado: %s\n", errorStyle.Render("Vulnerabilidad detectada")))
				}
				fullContent.WriteString("\n")
			}
		}
		fullContent.WriteString("\n")
	}

	// Recomendaciones principales
	if len(m.scanResult.Recommendations) > 0 {
		fullContent.WriteString("💡 RECOMENDACIONES PRINCIPALES:\n")
		fullContent.WriteString(strings.Repeat("─", 40) + "\n")
		maxRecs := min(5, len(m.scanResult.Recommendations))
		for i := 0; i < maxRecs; i++ {
			fullContent.WriteString(fmt.Sprintf("%d. %s\n", i+1, m.scanResult.Recommendations[i]))
		}
		if len(m.scanResult.Recommendations) > 5 {
			fullContent.WriteString(fmt.Sprintf("   ... y %d recomendaciones más (ver detalles)\n", len(m.scanResult.Recommendations)-5))
		}
		fullContent.WriteString("\n")
	}

	fullContent.WriteString("🎮 OPCIONES:\n")
	fullContent.WriteString("   [D/Enter] Ver detalles completos\n")
	fullContent.WriteString("   [R] Repetir escaneo\n")
	fullContent.WriteString("   [S] Guardar reporte\n")
	fullContent.WriteString("   [Backspace] Nuevo escaneo\n")
	fullContent.WriteString("   [Q/Esc] Salir\n")

	// Aplicar scroll - dividir contenido en líneas
	lines := strings.Split(fullContent.String(), "\n")
	totalLines := len(lines)

	// Calcular cuántas líneas caben en la pantalla (reservar espacio para header y footer)
	availableHeight := m.height - 6 // Header + footer + márgenes
	if availableHeight < 10 {
		availableHeight = 10 // Mínimo
	}

	// Ajustar scrollOffset para no ir más allá del contenido
	maxScroll := totalLines - availableHeight
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.scrollOffset > maxScroll {
		// Actualizar el modelo (necesario para reflejar el cambio)
		// Nota: Esto es un poco hacky, pero necesario para limitar el scroll
		m.scrollOffset = maxScroll
	}

	// Seleccionar las líneas visibles
	startLine := m.scrollOffset
	endLine := startLine + availableHeight
	if endLine > totalLines {
		endLine = totalLines
	}

	visibleLines := lines[startLine:endLine]

	// Agregar indicador de scroll si es necesario
	scrollContent := strings.Join(visibleLines, "\n")
	if totalLines > availableHeight {
		scrollContent += fmt.Sprintf("\n\n💡 NAVEGACIÓN: [↑↓] Línea | [PgUp/PgDn] Página | [Home/End] Inicio/Final | Línea %d-%d de %d",
			startLine+1, endLine, totalLines)
	}

	sb.WriteString(scrollContent)
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
		help.WriteString("↑↓ Navegar | PgUp/PgDn Página | Space Seleccionar | A Todos | N Ninguno | R Recomendados | V Verbose | X Avanzados | Enter Continuar")
	case StateFormat:
		help.WriteString("↑↓ Navegar | Space Seleccionar | V Verbose | Enter Continuar")
	case StateConfirm:
		help.WriteString("↑↓ Navegar | Space Seleccionar | Enter Confirmar | Esc Volver")
	case StateScanning:
		help.WriteString("Q Cancelar escaneo")
	case StateFinishing:
		help.WriteString("Generando reporte... Por favor espere")
	case StateResults:
		help.WriteString("↑↓ Scroll | PgUp/PgDn Página | D Detalles | R Repetir | S Guardar | Backspace Nuevo | Q Salir")
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
	_ = (m.width - modalWidth) / 2   // modalX no se usa
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

// renderTestsInColumns renderiza los tests en formato de columnas compactas con scroll
func (m Model) renderTestsInColumns() string {
	var sb strings.Builder

	// Asegurar que el modelo tenga scroll configurado
	model := m.adjustScrollPosition()

	// Configuración de visualización
	testsToShow := model.testsPerPage
	if testsToShow == 0 {
		testsToShow = max(5, model.height-25) // Fallback
	}

	// Determinar qué tests mostrar basado en el scroll
	startIndex := model.scrollOffset
	endIndex := min(len(model.tests), startIndex+testsToShow)

	// Mostrar indicador de scroll si es necesario
	if model.showScrollbar && len(model.tests) > testsToShow {
		totalTests := len(model.tests)
		currentPos := startIndex + 1
		endPos := min(totalTests, startIndex+testsToShow)

		sb.WriteString(fmt.Sprintf("📄 Mostrando tests %d-%d de %d total",
			currentPos, endPos, totalTests))

		// Barra de scroll visual
		scrollBarWidth := 20
		scrollProgress := float64(startIndex) / float64(totalTests-testsToShow)
		scrollPos := int(scrollProgress * float64(scrollBarWidth))

		scrollBar := strings.Repeat("─", scrollPos) + "█" + strings.Repeat("─", scrollBarWidth-scrollPos)
		sb.WriteString(fmt.Sprintf(" [%s]\n", scrollBar))
		sb.WriteString("\n")
	}

	// Configuración de columnas
	columnsCount := 2       // Reducir a 2 columnas para más espacio
	maxTestNameLength := 35 // Aumentar longitud del nombre

	// Crear una lista simple de tests a mostrar
	visibleTests := model.tests[startIndex:endIndex]

	// Renderizar en columnas simples
	for i := 0; i < len(visibleTests); i += columnsCount {
		for col := 0; col < columnsCount; col++ {
			if i+col >= len(visibleTests) {
				break
			}

			test := visibleTests[i+col]
			globalIndex := startIndex + i + col // Índice real en la lista completa

			// Crear el contenido del test
			marker := "☐"
			if test.Selected {
				marker = "☑"
			}

			recommended := ""
			if test.Recommended {
				recommended = " ⭐"
			}

			// Truncar nombre si es muy largo
			testName := test.Name
			if len(testName) > maxTestNameLength {
				testName = testName[:maxTestNameLength-3] + "..."
			}

			// Determinar estilo
			style := normalStyle
			prefix := " "
			if globalIndex == model.cursor {
				style = focusedStyle
				prefix = "→"
			}

			// Crear la línea del test con padding fijo
			testLine := fmt.Sprintf("%s%s %s%s", prefix, marker, testName, recommended)
			paddedLine := fmt.Sprintf("%-50s", testLine) // Padding fijo de 50 caracteres

			sb.WriteString(style.Render(paddedLine))

			// Agregar separador entre columnas (excepto en la última)
			if col < columnsCount-1 && i+col+1 < len(visibleTests) {
				sb.WriteString(" | ")
			}
		}
		sb.WriteString("\n")
	}

	// Mostrar descripción del test enfocado
	if model.cursor >= 0 && model.cursor < len(model.tests) {
		focusedTest := model.tests[model.cursor]
		sb.WriteString("\n")
		sb.WriteString(warningStyle.Render("─────────────────────────────────────────────────────────────────────"))
		sb.WriteString("\n")
		sb.WriteString(warningStyle.Render(fmt.Sprintf("📋 %s", focusedTest.Description)))
		sb.WriteString("\n")
		sb.WriteString(warningStyle.Render(fmt.Sprintf("🏷️ Categoría: %s (%s)", focusedTest.Category, getCategoryDescription(focusedTest.Category))))
		sb.WriteString("\n")
		sb.WriteString(warningStyle.Render("─────────────────────────────────────────────────────────────────────"))
		sb.WriteString("\n")
	}

	// Mostrar controles de scroll si es necesario
	if model.showScrollbar {
		sb.WriteString("\n💡 NAVEGACIÓN: [↑↓] Test anterior/siguiente | [PgUp/PgDn] Página anterior/siguiente | [Home/End] Inicio/Final\n")
	}

	return sb.String()
}
