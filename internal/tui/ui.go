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
	State  State
	Cursor int
	Width  int
	Height int

	// Configuración
	UseHTTPS         bool
	URL              string
	Profiles         []ProfileItem
	Tests            []TestItem
	Formats          []FormatItem
	Verbose          bool
	UseAdvancedTests bool
	OutputFile       string

	// Escaneo
	Scanning     bool
	ScanProgress ScanProgress
	ScanResult   *scanner.ScanResult
	SkipChannel  chan bool          // Canal para enviar comandos de skip durante el escaneo
	ScanContext  context.Context    // Context para cancelar el escaneo
	ScanCancel   context.CancelFunc // Función para cancelar el escaneo

	// Finalización
	FinishingSpinner int
	FinishingStart   time.Time
	FinishingElapsed time.Duration

	// Scroll/Paginación
	ScrollOffset  int  // Offset para el scroll de tests
	TestsPerPage  int  // Número de tests por página
	ShowScrollbar bool // Mostrar indicador de scroll

	// Error
	Err error

	// Notificaciones
	LastNotification string
	NotificationTime time.Time
}

// Init inicializa el modelo
func (m Model) Init() tea.Cmd {
	return nil
}

// Update maneja los mensajes y actualiza el estado
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Primero manejar mensajes de escaneo
	newModel, cmd := m.UpdateWithScanMessages(msg)
	if cmd != nil {
		return newModel, cmd
	}
	// Siempre usar el modelo actualizado, incluso si cmd es nil
	if UpdatedModel, ok := newModel.(Model); ok {
		m = UpdatedModel
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		return m, nil

	case tea.KeyMsg:
		// Teclas globales
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "v":
			m.Verbose = !m.Verbose
			return m, nil
		}

		// Manejo por estado
		switch m.State {
		case StateProtocol:
			return m.HandleProtocolKeys(msg)
		case StateURL:
			return m.HandleURLKeys(msg)
		case StateProfile:
			return m.HandleProfileKeys(msg)
		case StateTests:
			return m.HandleTestsKeys(msg)
		case StateFormat:
			return m.HandleFormatKeys(msg)
		case StateConfirm:
			return m.HandleConfirmKeys(msg)
		case StateScanning:
			return m.HandleScanningKeys(msg)
		case StateResults:
			return m.HandleResultsKeys(msg)
		}
	}

	return m, nil
}

// View renderiza la interfaz
func (m Model) View() string {
	if m.Width == 0 {
		return "Cargando..."
	}

	s := strings.Builder{}

	// Header
	s.WriteString(m.RenderHeader())
	s.WriteString("\n\n")

	// Contenido principal basado en el estado
	switch m.State {
	case StateProtocol:
		s.WriteString(m.RenderProtocolStep())
	case StateURL:
		s.WriteString(m.RenderURLStep())
	case StateProfile:
		s.WriteString(m.RenderProfileStep())
	case StateTests:
		s.WriteString(m.RenderTestsStep())
	case StateFormat:
		s.WriteString(m.RenderFormatStep())
	case StateConfirm:
		s.WriteString(m.RenderConfirmStep())
	case StateScanning:
		s.WriteString(m.RenderScanningStep())
	case StateFinishing:
		s.WriteString(m.RenderFinishingStep())
	case StateResults:
		s.WriteString(m.RenderResultsStep())
	}

	// Footer
	s.WriteString("\n\n")
	s.WriteString(m.RenderFooter())

	return s.String()
}

// NewModel crea un nuevo modelo inicializado
func NewModel() Model {
	// Cargar configuración principal desde config.json
	MainConfig, Err := config.LoadConfig("config.json")
	if Err != nil {
		// Si hay error cargando config, usar valores por defecto
		MainConfig = config.DefaultConfig()
	}

	// Generar lista de tests desde la fuente unificada
	AvailableTests := config.GetAvailableTests()
	Tests := make([]TestItem, len(AvailableTests))

	for i, TestDef := range AvailableTests {
		Tests[i] = TestItem{
			ID:          TestDef.ID,
			Name:        TestDef.Name,
			Description: TestDef.Description,
			Category:    TestDef.Category,
			Recommended: TestDef.Recommended,
			Selected:    MainConfig.IsTestEnabled(TestDef.ID), // Cargar estado desde config.json
		}
	}

	// Configurar formatos de salida
	Formats := []FormatItem{
		{ID: "json", Name: "JSON", Description: "Formato estructurado para integración"},
		{ID: "table", Name: "Tabla ASCII", Description: "Visualización clara en terminal"},
		{ID: "html", Name: "HTML", Description: "Reporte profesional con gráficos"},
	}
	Formats[1].Selected = true // Tabla ASCII por defecto

	// Configurar perfiles de escaneo
	Profiles := []ProfileItem{
		{
			ID:          "basic",
			Name:        MainConfig.ScanProfiles.Basic.Name,
			Description: MainConfig.ScanProfiles.Basic.Description,
			Timeout:     MainConfig.ScanProfiles.Basic.Timeout,
			Concurrent:  MainConfig.ScanProfiles.Basic.Concurrent,
			TestCount:   MainConfig.CountEnabledTests("basic"),
			Selected:    false,
		},
		{
			ID:          "standard",
			Name:        MainConfig.ScanProfiles.Standard.Name,
			Description: MainConfig.ScanProfiles.Standard.Description,
			Timeout:     MainConfig.ScanProfiles.Standard.Timeout,
			Concurrent:  MainConfig.ScanProfiles.Standard.Concurrent,
			TestCount:   MainConfig.CountEnabledTests("standard"),
			Selected:    true, // Estándar por defecto
		},
		{
			ID:          "advanced",
			Name:        MainConfig.ScanProfiles.Advanced.Name,
			Description: MainConfig.ScanProfiles.Advanced.Description,
			Timeout:     MainConfig.ScanProfiles.Advanced.Timeout,
			Concurrent:  MainConfig.ScanProfiles.Advanced.Concurrent,
			TestCount:   MainConfig.CountEnabledTests("advanced"),
			Selected:    false,
		},
	}

	// Cargar configuración TUI guardada
	TUIConfig := config.LoadTUIConfig()

	// Determinar estado inicial y configuración
	var InitialState State = StateProtocol
	var InitialURL string = ""
	var InitialHTTPS bool = true

	// Si hay configuración guardada y AutoStart está activo, cargar datos
	// SIEMPRE pasar por StateProfile para selección de perfil
	if TUIConfig.AutoStart && TUIConfig.LastUsedURL != "" {
		InitialState = StateProfile // Cambiado: siempre pasar por selección de perfil
		InitialURL = TUIConfig.LastUsedURL
		InitialHTTPS = TUIConfig.LastProtocol
	}

	// Encontrar el cursor inicial basado en el perfil seleccionado por defecto
	InitialCursor := 0
	for i, Profile := range Profiles {
		if Profile.Selected {
			InitialCursor = i
			break
		}
	}

	return Model{
		State:            InitialState,
		Cursor:           InitialCursor, // Cursor sincronizado con perfil seleccionado
		UseHTTPS:         InitialHTTPS,
		URL:              InitialURL,
		Profiles:         Profiles,
		Tests:            Tests,
		Formats:          Formats,
		Verbose:          MainConfig.Verbose,                // Cargar desde config.json
		UseAdvancedTests: MainConfig.Tests.UseAdvancedTests, // Cargar desde config.json
		ScrollOffset:     0,
		TestsPerPage:     15, // Valor inicial que se ajustará dinámicamente
		ShowScrollbar:    false,
	}
}

// RunTUI ejecuta la aplicación TUI
func RunTUI() error {
	m := NewModel()
	p := tea.NewProgram(m, tea.WithAltScreen())

	if _, Err := p.Run(); Err != nil {
		return fmt.Errorf("ErrorEjecutando TUI: %w", Err)
	}

	return nil
}
