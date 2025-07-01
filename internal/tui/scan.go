package tui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/versaSecurityTest/internal/config"
	"github.com/versaSecurityTest/internal/report"
	"github.com/versaSecurityTest/internal/scanner"
)

// startScan inicia el proceso de escaneo usando funciones unificadas
func (m Model) startScan() tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		// Construir URL completa
		protocol := "https://"
		if !m.useHTTPS {
			protocol = "http://"
		}
		fullURL := protocol + m.url

		// Crear mapa de tests habilitados
		enabledTests := make(map[string]bool)
		for _, test := range m.tests {
			enabledTests[test.ID] = test.Selected
		}

		// Crear canal de skip para TUI
		skipChannel := make(chan bool, 1)

		// Crear opciones de escaneo
		scanOptions := scanner.ScanOptions{
			TargetURL:        fullURL,
			ConfigFile:       "config.json",
			Verbose:          m.verbose,
			Concurrent:       10,               // Por defecto
			Timeout:          30 * time.Second, // Por defecto
			UseAdvancedTests: m.useAdvancedTests,
			EnabledTests:     enabledTests,
			SkipChannel:      skipChannel, // Pasar canal de skip al scanner
		}

		// Almacenar canal en el mensaje para poder usarlo después
		return ScanStartedMsg{
			Options:     scanOptions,
			SkipChannel: skipChannel,
		}
	})
}

// ScanCompleteMsg es el mensaje enviado cuando el escaneo se completa
type ScanCompleteMsg struct {
	Result *scanner.ScanResult
	Error  error
}

// ScanStartedMsg es el mensaje enviado cuando el escaneo inicia 
type ScanStartedMsg struct {
	Options     scanner.ScanOptions
	SkipChannel chan bool
}

// ScanProgressMsg es el mensaje enviado para actualizar el progreso
type ScanProgressMsg struct {
	Progress ScanProgress
}

// countSelectedTests cuenta cuántos tests están seleccionados
func countSelectedTests(tests []TestItem) int {
	count := 0
	for _, test := range tests {
		if test.Selected {
			count++
		}
	}
	return count
}

// handleScanComplete maneja la finalización del escaneo
func (m Model) handleScanComplete(msg ScanCompleteMsg) (Model, tea.Cmd) {
	m.scanning = false

	if msg.Error != nil {
		m.err = msg.Error
		// Podríamos mostrar un modal de error
		m.showModal = true
		m.modalTitle = "Error en el Escaneo"
		m.modalContent = fmt.Sprintf("Se produjo un error durante el escaneo:\n\n%s", msg.Error.Error())
		return m, nil
	}

	m.scanResult = msg.Result
	m.state = StateResults
	m.cursor = 0

	// Auto-guardar si está configurado
	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		cfg = config.DefaultConfig()
	}

	if cfg.AutoSave {
		err := m.autoSaveReport()
		if err != nil {
			// Mostrar advertencia pero no bloquear
			m.showModal = true
			m.modalTitle = "⚠️ Auto-guardado"
			m.modalContent = fmt.Sprintf("El escaneo se completó exitosamente, pero hubo un problema con el auto-guardado:\n\n%s\n\nPuede guardar manualmente presionando 's'.", err.Error())
		} else {
			// Notificar que se guardó automáticamente
			m.showModal = true
			m.modalTitle = "✅ Escaneo Completado"
			m.modalContent = "El escaneo se completó exitosamente y el reporte se guardó automáticamente en el directorio 'reports'.\n\nPresione Enter para continuar o 's' para guardar en otro formato."
		}
	}

	return m, nil
}

// saveReport guarda el reporte en el formato seleccionado
func (m Model) saveReport() error {
	if m.scanResult == nil {
		return fmt.Errorf("no hay resultados para guardar")
	}

	// Determinar formato seleccionado
	var format string = "table" // Por defecto tabla ASCII
	for _, f := range m.formats {
		if f.Selected {
			format = f.ID
			break
		}
	}

	// Usar función unificada para guardar reporte
	options := report.ReportOptions{
		Format:        format,
		UseReportsDir: true, // Siempre usar directorio reports/
	}

	savedFile, err := report.SaveReport(m.scanResult, options)
	if err != nil {
		return err
	}

	// Informar al usuario donde se guardó
	fmt.Printf("📄 Reporte guardado en: %s\n", savedFile)
	return nil
}

// autoSaveReport guarda automáticamente el reporte usando función unificada
func (m Model) autoSaveReport() error {
	if m.scanResult == nil {
		return fmt.Errorf("no hay resultados para guardar")
	}

	// Usar función unificada para auto-guardado
	savedFile, err := report.AutoSaveReport(m.scanResult)
	if err != nil {
		return fmt.Errorf("error guardando archivo automático: %w", err)
	}

	fmt.Printf("💾 Auto-guardado: Reporte guardado en %s\n", savedFile)
	return nil
}

// Actualizar el método Update principal para manejar mensajes de escaneo
func (m Model) updateWithScanMessages(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case ScanStartedMsg:
		// Guardar el canal de skip en el modelo
		m.skipChannel = msg.SkipChannel
		// Iniciar escaneo en background
		return m, m.executeBackgroundScan(msg.Options)
		
	case ScanCompleteMsg:
		return m.handleScanComplete(msg)
	}

	return m, nil
}

// executeBackgroundScan ejecuta el escaneo en background
func (m Model) executeBackgroundScan(options scanner.ScanOptions) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		// Ejecutar escaneo usando función unificada (TESTS REALES)
		scanResult, err := scanner.ExecuteScan(options)
		if err != nil {
			return ScanCompleteMsg{
				Result: nil,
				Error:  err,
			}
		}

		return ScanCompleteMsg{
			Result: scanResult,
			Error:  nil,
		}
	})
}
