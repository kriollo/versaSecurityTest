package tui

import (
	"context"
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
	StateProfile // Nuevo estado para selección de perfil
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

// ProfileItem representa un perfil de escaneo
type ProfileItem struct {
	ID          string
	Name        string
	Description string
	Timeout     time.Duration
	Concurrent  int
	TestCount   int
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
	useHTTPS         bool
	url              string
	profiles         []ProfileItem
	tests            []TestItem
	formats          []FormatItem
	verbose          bool
	useAdvancedTests bool
	outputFile       string

	// Escaneo
	scanning     bool
	scanProgress ScanProgress
	scanResult   *scanner.ScanResult
	skipChannel  chan bool          // Canal para enviar comandos de skip durante el escaneo
	scanContext  context.Context    // Context para cancelar el escaneo
	scanCancel   context.CancelFunc // Función para cancelar el escaneo

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
		case StateProfile:
			return m.handleProfileKeys(msg)
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
	case StateProfile:
		s.WriteString(m.renderProfileStep())
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
	// Cargar configuración principal desde config.json
	mainConfig, err := config.LoadConfig("config.json")
	if err != nil {
		// Si hay error cargando config, usar valores por defecto
		mainConfig = config.DefaultConfig()
	}

	// Generar lista de tests desde la fuente unificada
	availableTests := config.GetAvailableTests()
	tests := make([]TestItem, len(availableTests))

	for i, testDef := range availableTests {
		tests[i] = TestItem{
			ID:          testDef.ID,
			Name:        testDef.Name,
			Description: testDef.Description,
			Category:    testDef.Category,
			Recommended: testDef.Recommended,
			Selected:    mainConfig.IsTestEnabled(testDef.ID), // Cargar estado desde config.json
		}
	}

	// Configurar formatos de salida
	formats := []FormatItem{
		{ID: "json", Name: "JSON", Description: "Formato estructurado para integración"},
		{ID: "table", Name: "Tabla ASCII", Description: "Visualización clara en terminal"},
		{ID: "html", Name: "HTML", Description: "Reporte profesional con gráficos"},
	}
	formats[1].Selected = true // Tabla ASCII por defecto

	// Configurar perfiles de escaneo
	profiles := []ProfileItem{
		{
			ID:          "basic",
			Name:        mainConfig.ScanProfiles.Basic.Name,
			Description: mainConfig.ScanProfiles.Basic.Description,
			Timeout:     mainConfig.ScanProfiles.Basic.Timeout,
			Concurrent:  mainConfig.ScanProfiles.Basic.Concurrent,
			TestCount:   mainConfig.CountEnabledTests("basic"),
			Selected:    false,
		},
		{
			ID:          "standard",
			Name:        mainConfig.ScanProfiles.Standard.Name,
			Description: mainConfig.ScanProfiles.Standard.Description,
			Timeout:     mainConfig.ScanProfiles.Standard.Timeout,
			Concurrent:  mainConfig.ScanProfiles.Standard.Concurrent,
			TestCount:   mainConfig.CountEnabledTests("standard"),
			Selected:    true, // Estándar por defecto
		},
		{
			ID:          "advanced",
			Name:        mainConfig.ScanProfiles.Advanced.Name,
			Description: mainConfig.ScanProfiles.Advanced.Description,
			Timeout:     mainConfig.ScanProfiles.Advanced.Timeout,
			Concurrent:  mainConfig.ScanProfiles.Advanced.Concurrent,
			TestCount:   mainConfig.CountEnabledTests("advanced"),
			Selected:    false,
		},
	}

	// Cargar configuración TUI guardada
	tuiConfig := config.LoadTUIConfig()

	// Determinar estado inicial y configuración
	var initialState State = StateProtocol
	var initialURL string = ""
	var initialHTTPS bool = true

	// Si hay configuración guardada y AutoStart está activo, cargar datos
	// SIEMPRE pasar por StateProfile para selección de perfil
	if tuiConfig.AutoStart && tuiConfig.LastUsedURL != "" {
		initialState = StateProfile // Cambiado: siempre pasar por selección de perfil
		initialURL = tuiConfig.LastUsedURL
		initialHTTPS = tuiConfig.LastProtocol
	}

	// Encontrar el cursor inicial basado en el perfil seleccionado por defecto
	initialCursor := 0
	for i, profile := range profiles {
		if profile.Selected {
			initialCursor = i
			break
		}
	}

	return Model{
		state:            initialState,
		cursor:           initialCursor, // Cursor sincronizado con perfil seleccionado
		useHTTPS:         initialHTTPS,
		url:              initialURL,
		profiles:         profiles,
		tests:            tests,
		formats:          formats,
		verbose:          mainConfig.Verbose,                // Cargar desde config.json
		useAdvancedTests: mainConfig.Tests.UseAdvancedTests, // Cargar desde config.json
		scrollOffset:     0,
		testsPerPage:     15, // Valor inicial que se ajustará dinámicamente
		showScrollbar:    false,
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
