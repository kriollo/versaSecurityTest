package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/versaSecurityTest/internal/config"
	"github.com/versaSecurityTest/internal/report"
	"github.com/versaSecurityTest/internal/scanner"
)

// startScan inicia el proceso de escaneo
func (m Model) startScan() tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		// Construir URL completa
		protocol := "https://"
		if !m.useHTTPS {
			protocol = "http://"
		}
		fullURL := protocol + m.url

		// Crear configuración del scanner
		cfg := createScanConfig(m)

		// Inicializar el escáner
		webScanner := scanner.NewWebScanner(cfg)

	// Simular progreso inicial
	_ = ScanProgress{
		CurrentTest: "Inicializando...",
		Completed:   0,
		Total:       countSelectedTests(m.tests),
		Duration:    0,
	}

		// Enviar mensaje de inicio
		go func() {
			time.Sleep(500 * time.Millisecond)
			// Aquí enviarías un mensaje de progreso
		}()

		// Ejecutar escaneo
		startTime := time.Now()
		scanResult := webScanner.ScanURL(fullURL)
		duration := time.Since(startTime)

		// Completar información del reporte
		scanResult.URL = fullURL
		scanResult.ScanDate = time.Now()
		scanResult.Duration = duration

		return ScanCompleteMsg{
			Result: scanResult,
			Error:  nil,
		}
	})
}

// ScanCompleteMsg es el mensaje enviado cuando el escaneo se completa
type ScanCompleteMsg struct {
	Result *scanner.ScanResult
	Error  error
}

// ScanProgressMsg es el mensaje enviado para actualizar el progreso
type ScanProgressMsg struct {
	Progress ScanProgress
}

// createScanConfig crea la configuración del scanner basada en las selecciones del usuario
func createScanConfig(m Model) *config.Config {
	cfg := config.DefaultConfig()
	
	// Configurar tests seleccionados
	cfg.Tests = config.TestConfig{
		SQLInjection:    isTestSelected(m.tests, "sql"),
		XSS:            isTestSelected(m.tests, "xss"),
		HTTPHeaders:    isTestSelected(m.tests, "headers"),
		SSLAnalysis:    isTestSelected(m.tests, "ssl"),
		CSRFProtection: isTestSelected(m.tests, "csrf"),
		BruteForce:     isTestSelected(m.tests, "bruteforce"),
		FileUpload:     isTestSelected(m.tests, "fileupload"),
		DirTraversal:   isTestSelected(m.tests, "dirtraversal"),
		InfoDisclosure: isTestSelected(m.tests, "info"),
	}
	
	// Configurar opciones generales
	cfg.Verbose = m.verbose
	cfg.Concurrent = 10 // Por defecto
	cfg.Timeout = 30 * time.Second // Por defecto
	
	return cfg
}

// isTestSelected verifica si un test específico está seleccionado
func isTestSelected(tests []TestItem, testID string) bool {
	for _, test := range tests {
		if test.ID == testID && test.Selected {
			return true
		}
	}
	return false
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
	
	return m, nil
}

// saveReport guarda el reporte en el formato seleccionado
func (m Model) saveReport() error {
	if m.scanResult == nil {
		return fmt.Errorf("no hay resultados para guardar")
	}
	
	// Determinar formato seleccionado
	var format string
	for _, f := range m.formats {
		if f.Selected {
			format = f.ID
			break
		}
	}
	
	// Generar contenido del reporte
	var content string
	var fileExt string
	
	switch format {
	case "json":
		jsonBytes, err := json.MarshalIndent(m.scanResult, "", "  ")
		if err != nil {
			return fmt.Errorf("error generando reporte JSON: %w", err)
		}
		content = string(jsonBytes)
		fileExt = ".json"
		
	case "html":
		content = report.GenerateHTMLReport(m.scanResult)
		fileExt = ".html"
		
	case "table":
		content = report.GenerateTableReport(m.scanResult)
		fileExt = ".txt"
		
	default:
		return fmt.Errorf("formato no soportado: %s", format)
	}
	
	// Generar nombre de archivo
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("security_report_%s%s", timestamp, fileExt)
	
	// Guardar archivo
	err := os.WriteFile(filename, []byte(content), 0644)
	if err != nil {
		return fmt.Errorf("error guardando archivo: %w", err)
	}
	
	return nil
}

// Actualizar el método Update principal para manejar mensajes de escaneo
func (m Model) updateWithScanMessages(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case ScanCompleteMsg:
		return m.handleScanComplete(msg)
		
	case ScanProgressMsg:
		m.scanProgress = msg.Progress
		return m, nil
	}
	
	return m, nil
}
