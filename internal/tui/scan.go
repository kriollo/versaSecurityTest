package tui

import (
	"context"
	"fmt"

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

		// Cargar configuración desde archivo (como lo hace CLI)
		cfg, err := config.LoadConfig("config.json")
		if err != nil {
			cfg = config.DefaultConfig()
		}

		// ACTUALIZAR config.json con la selección del usuario antes del escaneo
		// Esto asegura que ambos CLI y TUI usen la misma configuración
		for _, test := range m.tests {
			cfg.SetTestEnabled(test.ID, test.Selected)
		}
		cfg.Tests.UseAdvancedTests = m.useAdvancedTests
		cfg.Verbose = m.verbose

		// Guardar la configuración actualizada en config.json
		err = cfg.SaveConfig("config.json")
		if err != nil {
			// Si no se puede guardar, continuar con advertencia
			fmt.Printf("⚠️  Advertencia: No se pudo guardar configuración: %v\n", err)
		}

		// Crear canal de skip para TUI
		skipChannel := make(chan bool, 1)

		// Crear opciones de escaneo - AHORA SIN EnabledTests para que use config.json
		scanOptions := scanner.ScanOptions{
			TargetURL:        fullURL,
			ConfigFile:       "config.json",
			Verbose:          cfg.Verbose,
			Concurrent:       cfg.Concurrent,
			Timeout:          cfg.Timeout,
			UseAdvancedTests: cfg.Tests.UseAdvancedTests,
			EnabledTests:     nil, // Usar config.json (igual que CLI)
			SkipChannel:      skipChannel,
			ProgressCallback: m.createProgressCallback(), // Callback para progreso en tiempo real
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
	TestName  string
	Completed int
	Total     int
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

	// Limpiar context de cancelación
	if m.scanCancel != nil {
		m.scanCancel()
		m.scanCancel = nil
		m.scanContext = nil
	}

	if msg.Error != nil {
		m.err = msg.Error
		// Error durante el escaneo - continuar sin modal
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
			// Auto-guardado falló silenciosamente
			// El usuario puede guardar manualmente presionando 's'
		} else {
			// Se guardó automáticamente sin notificación
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
		// Crear context con cancelación para el escaneo
		ctx, cancel := context.WithCancel(context.Background())
		m.scanContext = ctx
		m.scanCancel = cancel

		// Guardar el canal de skip en el modelo
		m.skipChannel = msg.SkipChannel
		// Iniciar escaneo en background
		return m, m.executeBackgroundScan(msg.Options)

	case ScanCompleteMsg:
		return m.handleScanComplete(msg)

	case ScanProgressMsg:
		return m.handleProgressUpdate(msg)
	}

	return m, nil
}

// executeBackgroundScan ejecuta el escaneo en background con timeout
func (m Model) executeBackgroundScan(options scanner.ScanOptions) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		// Canal para recibir resultado del escaneo
		resultChan := make(chan *scanner.ScanResult, 1)
		errorChan := make(chan error, 1)

		// Ejecutar escaneo en goroutine separado
		// NOTA: No creamos context adicional aquí - el scanner maneja su propio timeout
		// Esto asegura que CLI y TUI usen exactamente la misma lógica de timeout
		go func() {
			defer func() {
				if r := recover(); r != nil {
					errorChan <- fmt.Errorf("panic durante escaneo: %v", r)
				}
			}()

			scanResult, err := scanner.ExecuteScan(options)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- scanResult
		}()

		// Esperar resultado - el scanner maneja timeout internamente
		select {
		case scanResult := <-resultChan:
			// Escaneo completado exitosamente
			return ScanCompleteMsg{
				Result: scanResult,
				Error:  nil,
			}

		case err := <-errorChan:
			// Error durante el escaneo
			return ScanCompleteMsg{
				Result: nil,
				Error:  err,
			}
		}
	})
}

// createProgressCallback crea un callback para reportar progreso en tiempo real
func (m Model) createProgressCallback() func(string, int, int) {
	return func(testName string, completed, total int) {
		// El callback se ejecuta en el goroutine del scanner
		// No podemos enviar comandos de Bubble Tea directamente aquí
		// En su lugar, el scanner ya muestra progreso en la consola
		// Para TUI, podríamos usar un channel pero sería complejo
		// Por ahora, dejamos que el scanner maneje el progreso interno
	}
}

// createProgressCmd crea un comando que actualiza el progreso
func (m Model) createProgressCmd(testName string, completed, total int) tea.Cmd {
	return func() tea.Msg {
		return ScanProgressMsg{
			TestName:  testName,
			Completed: completed,
			Total:     total,
		}
	}
}

// handleProgressUpdate maneja la actualización del progreso
func (m Model) handleProgressUpdate(msg ScanProgressMsg) (Model, tea.Cmd) {
	// Actualizar progreso en el modelo
	m.scanProgress.CurrentTest = msg.TestName
	m.scanProgress.Completed = msg.Completed
	m.scanProgress.Total = msg.Total
	return m, nil
}
