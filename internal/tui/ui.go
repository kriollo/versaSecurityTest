package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/versaSecurityTest/internal/config"
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
	StateFinishing // Nuevo estado para mostrar spinner mientras se generan resultados
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
	state  State
	cursor int
	width  int
	height int

	// Configuración
	useHTTPS   bool
	url        string
	tests      []TestItem
	formats    []FormatItem
	verbose    bool
	outputFile string

	// Escaneo
	scanning     bool
	scanProgress ScanProgress
	scanResult   *scanner.ScanResult

	// Finalización
	finishingSpinner int
	finishingStart   time.Time
	finishingElapsed time.Duration

	// Scroll/Paginación
	scrollOffset  int  // Offset para el scroll de tests
	testsPerPage  int  // Número de tests por página
	showScrollbar bool // Mostrar indicador de scroll

	// Modal
	showModal    bool
	modalContent string
	modalTitle   string

	// Error
	err error
}

// Init inicializa el modelo
func (m Model) Init() tea.Cmd {
	return nil
}

// Update maneja los mensajes y actualiza el estado
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Primero manejar mensajes de escaneo
	newModel, cmd := m.updateWithScanMessages(msg)
	if cmd != nil {
		return newModel, cmd
	}
	// Siempre usar el modelo actualizado, incluso si cmd es nil
	if updatedModel, ok := newModel.(Model); ok {
		m = updatedModel
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
	case StateFinishing:
		s.WriteString(m.renderFinishingStep())
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
		// Categoría INFO - Recolección de información
		{ID: "info_gathering", Name: "INFO-01: Information Gathering", Description: "Recolección de información del servidor", Category: "INFO", Recommended: true},
		{ID: "dir_enum", Name: "INFO-06: Directory Enumeration", Description: "Enumeración de directorios comunes", Category: "INFO", Recommended: true},
		{ID: "http_methods", Name: "INFO-07: HTTP Methods", Description: "Métodos HTTP habilitados", Category: "INFO", Recommended: false},

		// Categoría CONF - Configuración
		{ID: "configuration", Name: "CONF-01: Configuration", Description: "Verificación de configuración", Category: "CONF", Recommended: true},
		{ID: "default_pages", Name: "CONF-04: Default Pages", Description: "Páginas por defecto expuestas", Category: "CONF", Recommended: true},
		{ID: "error_handling", Name: "CONF-05: Error Handling", Description: "Manejo de errores", Category: "CONF", Recommended: false},

		// Categoría IDNT - Gestión de identidad
		{ID: "identity_mgmt", Name: "IDNT-01: Identity Management", Description: "Mecanismos de gestión de identidad", Category: "IDNT", Recommended: false},
		{ID: "user_enum", Name: "IDNT-05: User Enumeration", Description: "Enumeración de usuarios", Category: "IDNT", Recommended: false},

		// Categoría ATHN - Autenticación
		{ID: "bruteforce", Name: "ATHN-04: Brute Force", Description: "Vulnerabilidades de fuerza bruta", Category: "ATHN", Recommended: true},

		// Categoría ATHZ - Autorización
		{ID: "authorization", Name: "ATHZ-01: Authorization", Description: "Control de acceso y autorización", Category: "ATHZ", Recommended: true},
		{ID: "direct_object_ref", Name: "ATHZ-04: Direct Object Reference", Description: "Referencias directas inseguras", Category: "ATHZ", Recommended: true},

		// Categoría SESS - Gestión de sesiones
		{ID: "session_mgmt", Name: "SESS-01: Session Management", Description: "Gestión de sesiones y tokens", Category: "SESS", Recommended: true},

		// Categoría INPV - Validación de entrada
		{ID: "input_validation", Name: "INPV-01: Input Validation", Description: "Validación y saneamiento de entradas", Category: "INPV", Recommended: true},
		{ID: "data_validation", Name: "INPV-05: Data Validation", Description: "Validación de tipos de datos", Category: "INPV", Recommended: false},
		{ID: "sql_injection", Name: "INPV-07: SQL Injection", Description: "Inyección SQL", Category: "INPV", Recommended: true},
		{ID: "xss", Name: "INPV-11: Cross-Site Scripting", Description: "XSS reflejado y almacenado", Category: "INPV", Recommended: true},
		{ID: "dirtraversal", Name: "INPV-12: Directory Traversal", Description: "Vulnerabilidades de path traversal", Category: "INPV", Recommended: true},

		// Categoría ERRH - Manejo de errores
		{ID: "error_leakage", Name: "ERRH-01: Error Information Leakage", Description: "Filtración de información en errores", Category: "ERRH", Recommended: false},

		// Categoría CRYP - Criptografía
		{ID: "ssl_tls", Name: "CRYP-01: SSL/TLS Security", Description: "Configuración SSL/TLS", Category: "CRYP", Recommended: true},
		{ID: "cryptography", Name: "CRYP-02: Cryptography", Description: "Uso correcto de criptografía", Category: "CRYP", Recommended: false},

		// Categoría BUSL - Lógica de negocio
		{ID: "business_logic", Name: "BUSL-01: Business Logic", Description: "Lógica de negocio y procesos", Category: "BUSL", Recommended: false},

		// Categoría CLNT - Cliente
		{ID: "client_side", Name: "CLNT-01: Client-Side Security", Description: "Seguridad del lado del cliente", Category: "CLNT", Recommended: true},
		{ID: "http_headers", Name: "CLNT-02: Security Headers", Description: "Headers de seguridad HTTP", Category: "CLNT", Recommended: true},

		// Categoría APIT - APIs
		{ID: "api_security", Name: "APIT-01: API Security", Description: "Seguridad en APIs REST/GraphQL", Category: "APIT", Recommended: true},

		// Tests adicionales
		{ID: "csrf", Name: "CSRF Protection", Description: "Protección contra CSRF", Category: "MISC", Recommended: false},
		{ID: "fileupload", Name: "File Upload Security", Description: "Seguridad en carga de archivos", Category: "MISC", Recommended: false},
		{ID: "info_disclosure", Name: "Information Disclosure", Description: "Revelación de información sensible", Category: "MISC", Recommended: false},
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
	formats[1].Selected = true // Tabla ASCII por defecto

	// Cargar configuración TUI guardada
	tuiConfig := config.LoadTUIConfig()

	// Determinar estado inicial y configuración
	var initialState State = StateProtocol
	var initialURL string = ""
	var initialHTTPS bool = true

	// Si hay configuración guardada y AutoStart está activo, cargar datos
	if tuiConfig.AutoStart && tuiConfig.LastUsedURL != "" {
		initialState = StateTests
		initialURL = tuiConfig.LastUsedURL
		initialHTTPS = tuiConfig.LastProtocol
	}

	return Model{
		state:         initialState,
		useHTTPS:      initialHTTPS,
		url:           initialURL,
		tests:         tests,
		formats:       formats,
		verbose:       false,
		scrollOffset:  0,
		testsPerPage:  15, // Valor inicial que se ajustará dinámicamente
		showScrollbar: false,
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
