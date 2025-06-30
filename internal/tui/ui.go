package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/versaSecurityTest/internal/scanner"
)

// Estados de la interfaz
type State int

const (
	StateProtocol State = iota
	StateURL
	StateTests
	StateFormat
	StateConfirm
	StateScanning
	StateResults
)

// TestItem representa un test con su estado de selección
type TestItem struct {
	ID          string
	Name        string
	Description string
	Category    string
	Selected    bool
	Recommended bool
}

// FormatItem representa un formato de salida
type FormatItem struct {
	ID          string
	Name        string
	Description string
	Selected    bool
}

// ScanProgress representa el progreso del escaneo
type ScanProgress struct {
	CurrentTest     string
	Completed       int
	Total           int
	Duration        time.Duration
	CurrentTestTime time.Duration
	TestDetails     []TestProgress
	StartTime       time.Time
}

// TestProgress representa el progreso de un test individual
type TestProgress struct {
	Name      string
	Status    string // "running", "completed", "failed", "pending"
	Duration  time.Duration
	StartTime time.Time
	Message   string
}

// Model representa el estado completo de la TUI
type Model struct {
	state         State
	cursor        int
	width         int
	height        int
	
	// Configuración
	useHTTPS      bool
	url           string
	tests         []TestItem
	formats       []FormatItem
	verbose       bool
	outputFile    string
	
	// Escaneo
	scanning      bool
	scanProgress  ScanProgress
	scanResult    *scanner.ScanResult
	
	// Modal
	showModal     bool
	modalContent  string
	modalTitle    string
	
	// Error
	err           error
}

// Init inicializa el modelo
func (m Model) Init() tea.Cmd {
	return nil
}

// Update maneja los mensajes y actualiza el estado
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Primero manejar mensajes de escaneo
	if newModel, cmd := m.updateWithScanMessages(msg); cmd != nil {
		return newModel, cmd
	}
	
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	
	case tea.KeyMsg:
		// Si hay un modal abierto, manejarlo primero
		if m.showModal {
			return m.handleModalKeys(msg)
		}
		
		// Teclas globales
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "v":
			m.verbose = !m.verbose
			return m, nil
		}
		
		// Manejo por estado
		switch m.state {
		case StateProtocol:
			return m.handleProtocolKeys(msg)
		case StateURL:
			return m.handleURLKeys(msg)
		case StateTests:
			return m.handleTestsKeys(msg)
		case StateFormat:
			return m.handleFormatKeys(msg)
		case StateConfirm:
			return m.handleConfirmKeys(msg)
		case StateScanning:
			return m.handleScanningKeys(msg)
		case StateResults:
			return m.handleResultsKeys(msg)
		}
	}
	
	return m, nil
}

// View renderiza la interfaz
func (m Model) View() string {
	if m.width == 0 {
		return "Cargando..."
	}
	
	s := strings.Builder{}
	
	// Header
	s.WriteString(m.renderHeader())
	s.WriteString("\n\n")
	
	// Contenido principal basado en el estado
	switch m.state {
	case StateProtocol:
		s.WriteString(m.renderProtocolStep())
	case StateURL:
		s.WriteString(m.renderURLStep())
	case StateTests:
		s.WriteString(m.renderTestsStep())
	case StateFormat:
		s.WriteString(m.renderFormatStep())
	case StateConfirm:
		s.WriteString(m.renderConfirmStep())
	case StateScanning:
		s.WriteString(m.renderScanningStep())
	case StateResults:
		s.WriteString(m.renderResultsStep())
	}
	
	// Footer
	s.WriteString("\n\n")
	s.WriteString(m.renderFooter())
	
	// Modal si está activo
	if m.showModal {
		return m.renderModal(s.String())
	}
	
	return s.String()
}

// NewModel crea un nuevo modelo inicializado
func NewModel() Model {
	tests := []TestItem{
		{ID: "basic", Name: "Conectividad Básica", Description: "Pruebas fundamentales de conectividad", Category: "Core", Recommended: true},
		{ID: "sql", Name: "SQL Injection", Description: "Detecta vulnerabilidades de inyección SQL", Category: "Injection", Recommended: true},
		{ID: "xss", Name: "Cross-Site Scripting", Description: "Identifica vectores de ataque XSS", Category: "Injection", Recommended: true},
		{ID: "headers", Name: "Headers de Seguridad", Description: "Verifica headers HTTP de seguridad", Category: "Config", Recommended: true},
		{ID: "ssl", Name: "SSL/TLS Security", Description: "Analiza configuración SSL", Category: "Crypto", Recommended: false},
		{ID: "csrf", Name: "CSRF Protection", Description: "Verifica protección contra CSRF", Category: "Auth", Recommended: false},
		{ID: "bruteforce", Name: "Brute Force", Description: "Detecta vulnerabilidades de fuerza bruta", Category: "Auth", Recommended: false},
		{ID: "fileupload", Name: "File Upload", Description: "Analiza seguridad en carga de archivos", Category: "Upload", Recommended: false},
		{ID: "dirtraversal", Name: "Directory Traversal", Description: "Detecta vulnerabilidades de path traversal", Category: "File", Recommended: false},
		{ID: "info", Name: "Information Disclosure", Description: "Detecta exposición de información", Category: "Info", Recommended: true},
	}
	
	// Marcar tests recomendados como seleccionados por defecto
	for i := range tests {
		tests[i].Selected = tests[i].Recommended
	}
	
	formats := []FormatItem{
		{ID: "json", Name: "JSON", Description: "Formato estructurado para integración"},
		{ID: "table", Name: "Tabla ASCII", Description: "Visualización clara en terminal"},
		{ID: "html", Name: "HTML", Description: "Reporte profesional con gráficos"},
	}
	formats[0].Selected = true // JSON por defecto
	
	return Model{
		state:    StateProtocol,
		useHTTPS: true, // HTTPS por defecto
		tests:    tests,
		formats:  formats,
		verbose:  false,
	}
}

// RunTUI ejecuta la aplicación TUI
func RunTUI() error {
	m := NewModel()
	p := tea.NewProgram(m, tea.WithAltScreen())
	
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error ejecutando TUI: %w", err)
	}
	
	return nil
}
