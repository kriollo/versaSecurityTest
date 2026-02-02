package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/versaSecurityTest/internal/config"
	"github.com/versaSecurityTest/internal/report"
	"github.com/versaSecurityTest/internal/scanner"
)

// StartScan inicia el proceso de escaneo usando funciones unificadas
func (m Model) StartScan() tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		// Construir URL completa
		protocol := "https://"
		if !m.UseHTTPS {
			protocol = "http://"
		}
		fullURL := protocol + m.URL

		// Crear mapa de Tests habilitados
		enabledTests := make(map[string]bool)
		for _, test := range m.Tests {
			enabledTests[test.ID] = test.Selected
		}

		// Cargar configuración desde archivo (como lo hace CLI)
		cfg, Err := config.LoadConfig("config.json")
		if Err != nil {
			cfg = config.DefaultConfig()
		}

		// ACTUALIZAR config.json con la selección del usuario antes del escaneo
		// Esto asegura que ambos CLI y TUI usen la misma configuración
		for _, test := range m.Tests {
			cfg.SetTestEnabled(test.ID, test.Selected)
		}
		cfg.Tests.UseAdvancedTests = m.UseAdvancedTests
		cfg.Verbose = m.Verbose

		// Guardar la configuración actualizada en config.json
		Err = cfg.SaveConfig("config.json")
		if Err != nil {
			// Si no se puede guardar, continuar con advertencia
			fmt.Printf("⚠️  Advertencia: No se pudo guardar configuración: %v\n", Err)
		}

		// Crear canal de skip para TUI
		SkipChannel := make(chan bool, 1)

		// Crear opciones de escaneo - AHORA SIN EnabledTests para que use config.json
		scanOptions := scanner.ScanOptions{
			TargetURL:        fullURL,
			ConfigFile:       "config.json",
			Verbose:          cfg.Verbose,
			Concurrent:       cfg.Concurrent,
			Timeout:          cfg.Timeout,
			UseAdvancedTests: cfg.Tests.UseAdvancedTests,
			EnabledTests:     nil, // Usar config.json (igual que CLI)
			SkipChannel:      SkipChannel,
			ProgressCallback: m.createProgressCallback(), // Callback para progreso en tiempo real
		}

		// Almacenar canal en el mensaje para poder usarlo después
		return ScanStartedMsg{
			Options:     scanOptions,
			SkipChannel: SkipChannel,
		}
	})
}

// ScanCompleteMsg es el mensaje enviado cuando el escaneo se completa
type ScanCompleteMsg struct {
	Result *scanner.ScanResult
	error  error
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

// TickMsg es el mensaje enviado para actualizar el timer cada segundo
type TickMsg time.Time

// doTick crea un comando que envía un TickMsg cada segundo
func doTick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// countSelectedTests cuenta cuántos Tests están seleccionados
func countSelectedTests(Tests []TestItem) int {
	count := 0
	for _, test := range Tests {
		if test.Selected {
			count++
		}
	}
	return count
}

// handleScanComplete maneja la finalización del escaneo
func (m Model) handleScanComplete(msg ScanCompleteMsg) (Model, tea.Cmd) {
	m.Scanning = false

	// Limpiar context de cancelación
	if m.ScanCancel != nil {
		m.ScanCancel()
		m.ScanCancel = nil
		m.ScanContext = nil
	}

	if msg.error != nil {
		m.Err = msg.error
		// error durante el escaneo - continuar sin modal
		return m, nil
	}

	m.ScanResult = msg.Result
	m.State = StateResults
	m.Cursor = 0

	// Auto-guardar si está configurado
	cfg, Err := config.LoadConfig("config.json")
	if Err != nil {
		cfg = config.DefaultConfig()
	}

	if cfg.AutoSave {
		Err := m.autoSaveReport()
		if Err != nil {
			// Auto-guardado falló silenciosamente
			// El usuario puede guardar manualmente presionando 's'
		} else {
			// Se guardó automáticamente sin notificación
		}
	}

	return m, nil
}

// SaveReport guarda el reporte en el formato seleccionado
func (m *Model) SaveReport() error {
	if m.ScanResult == nil {
		return fmt.Errorf("no hay resultados para guardar")
	}

	// Determinar formato seleccionado
	var format string = "table" // Por defecto tabla ASCII
	for _, f := range m.Formats {
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

	savedFile, Err := report.SaveReport(m.ScanResult, options)
	if Err != nil {
		return Err
	}

	// Informar al usuario donde se guardó actualizando el modelo
	m.LastNotification = fmt.Sprintf("📄 Reporte guardado en: %s", savedFile)
	m.NotificationTime = time.Now()
	return nil
}

// autoSaveReport guarda automáticamente el reporte usando el formato seleccionado
func (m *Model) autoSaveReport() error {
	if m.ScanResult == nil {
		return fmt.Errorf("no hay resultados para guardar")
	}

	// Determinar formato seleccionado
	var format string = "json" // Por defecto JSON para auto-guardado
	for _, f := range m.Formats {
		if f.Selected {
			format = f.ID
			break
		}
	}

	// Usar función unificada para guardado con el formato seleccionado
	options := report.ReportOptions{
		Format:        format,
		UseReportsDir: true,
	}

	savedFile, Err := report.SaveReport(m.ScanResult, options)
	if Err != nil {
		return fmt.Errorf("error guardando archivo automático: %w", Err)
	}

	// Notificar al modelo para que la TUI lo muestre
	m.LastNotification = fmt.Sprintf("💾 Auto-guardado: Reporte guardado en %s", savedFile)
	m.NotificationTime = time.Now()
	return nil
}

// Actualizar el método Update principal para manejar mensajes de escaneo
func (m Model) UpdateWithScanMessages(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case ScanStartedMsg:
		// Crear context con cancelación para el escaneo
		ctx, cancel := context.WithCancel(context.Background())
		m.ScanContext = ctx
		m.ScanCancel = cancel

		// Guardar el canal de skip en el modelo
		m.SkipChannel = msg.SkipChannel
		// Iniciar escaneo en background Y el timer
		return m, tea.Batch(m.executeBackgroundScan(msg.Options), doTick())

	case ScanCompleteMsg:
		return m.handleScanComplete(msg)

	case ScanProgressMsg:
		return m.handleProgressUpdate(msg)

	case TickMsg:
		if m.Scanning {
			return m, doTick()
		}
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

			ScanResult, Err := scanner.ExecuteScan(options)
			if Err != nil {
				errorChan <- Err
				return
			}
			resultChan <- ScanResult
		}()

		// Esperar resultado - el scanner maneja timeout internamente
		select {
		case ScanResult := <-resultChan:
			// Escaneo completado exitosamente
			return ScanCompleteMsg{
				Result: ScanResult,
				error:  nil,
			}

		case Err := <-errorChan:
			// error durante el escaneo
			return ScanCompleteMsg{
				Result: nil,
				error:  Err,
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
	m.ScanProgress.CurrentTest = msg.TestName
	m.ScanProgress.Completed = msg.Completed
	m.ScanProgress.Total = msg.Total
	return m, nil
}
