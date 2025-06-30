package cli

import "time"

// InteractiveConfig contiene la configuración de la CLI interactiva
type InteractiveConfig struct {
	URL           string        `json:"url"`
	SelectedTests []string      `json:"selected_tests"`
	ReportFormat  string        `json:"report_format"`
	OutputFile    string        `json:"output_file"`
	Verbose       bool          `json:"verbose"`
	Concurrent    int           `json:"concurrent"`
	Timeout       time.Duration `json:"timeout"`
}

// TestOption representa un test disponible en el menú interactivo
type TestOption struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`     // Indica si está en la selección recomendada
	Category    string `json:"category"`    // Categoría del test (opcional)
	Severity    string `json:"severity"`    // Severidad esperada (opcional)
}

// FormatOption representa un formato de reporte disponible
type FormatOption struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Extension   string `json:"extension"` // Extensión de archivo sugerida
}

// MenuState mantiene el estado de la navegación en menus
type MenuState struct {
	CurrentMenu     string                 `json:"current_menu"`
	SelectedOptions map[string]interface{} `json:"selected_options"`
	History         []string               `json:"history"`
}

// ValidationResult representa el resultado de validación de entrada
type ValidationResult struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
	Value   interface{} `json:"value"`
}
