package tests

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/versaSecurityTest/internal/config"
)

// ConfigurationTest implementa tests de configuración y archivos sensibles
type ConfigurationTest struct{}

// Run ejecuta todos los tests de configuración
func (t *ConfigurationTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "Configuration Security",
		Status:      "Passed",
		Description: "Verificación de configuración y exposición de archivos sensibles",
		Severity:    "Info",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	// CONF-01: Acceso a archivos sensibles
	t.testSensitiveFiles(targetURL, client, &result)

	// CONF-02: Directorios sin protección
	t.testDirectoryListing(targetURL, client, &result)

	// CONF-03: Configuración incorrecta de servidor web
	t.testServerMisconfiguration(targetURL, client, &result)

	// CONF-04: Configuración errónea de CORS
	t.testCORSMisconfiguration(targetURL, client, &result)

	// CONF-05: Rutas internas expuestas
	t.testInternalPaths(targetURL, client, &result)

	// Determinar el estado final
	if len(result.Details) == 0 {
		result.Description = "No se encontraron problemas de configuración"
	} else {
		result.Status = "Failed"
		result.Description = fmt.Sprintf("Se encontraron %d problemas de configuración", len(result.Details))
		result.Severity = "High"
	}

	return result
}

// CONF-01: Acceso a archivos sensibles
func (t *ConfigurationTest) testSensitiveFiles(targetURL string, client HTTPClient, result *TestResult) {
	sensitiveFiles := []string{
		"/.env",
		"/.git/config",
		"/.git/HEAD",
		"/backup.zip",
		"/backup.sql",
		"/config.php",
		"/config.inc.php",
		"/configuration.php",
		"/wp-config.php",
		"/web.config",
		"/.htaccess",
		"/.htpasswd",
		"/composer.json",
		"/package.json",
		"/.dockerignore",
		"/Dockerfile",
		"/docker-compose.yml",
		"/.DS_Store",
		"/thumbs.db",
		"/phpinfo.php",
		"/info.php",
		"/test.php",
		"/admin.php",
		"/database.sql",
		"/dump.sql",
		"/error_log",
		"/access.log",
		"/.log",
		"/server-status",
		"/server-info",
	}

	baseURL := strings.TrimSuffix(targetURL, "/")

	for _, file := range sensitiveFiles {
		fullURL := baseURL + file

		// Crear request con timeout
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}

		quickClient := &http.Client{Timeout: 5 * time.Second}
		resp, err := quickClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			result.Details = append(result.Details, fmt.Sprintf("Archivo sensible accesible: %s (Status: %d)", file, resp.StatusCode))
			result.Evidence = append(result.Evidence, Evidence{
				Type:     "Sensitive File Exposure",
				URL:      fullURL,
				Response: fmt.Sprintf("HTTP %d - Sensitive file accessible", resp.StatusCode),
			})
		}
	}
}

// CONF-02: Directorios sin protección
func (t *ConfigurationTest) testDirectoryListing(targetURL string, client HTTPClient, result *TestResult) {
	directories := []string{
		"/admin/",
		"/backup/",
		"/config/",
		"/tmp/",
		"/temp/",
		"/uploads/",
		"/files/",
		"/images/",
		"/css/",
		"/js/",
		"/assets/",
		"/include/",
		"/includes/",
		"/logs/",
		"/log/",
	}

	baseURL := strings.TrimSuffix(targetURL, "/")

	for _, dir := range directories {
		fullURL := baseURL + dir

		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}

		quickClient := &http.Client{Timeout: 5 * time.Second}
		resp, err := quickClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, err := ReadResponseBody(resp)
			if err != nil {
				continue
			}

			// Buscar indicadores de directory listing
			listingIndicators := []string{
				"Index of /",
				"Directory Listing",
				"<title>Index of",
				"Parent Directory",
				"[DIR]",
				"[TXT]",
				"Last modified",
			}

			for _, indicator := range listingIndicators {
				if strings.Contains(body, indicator) {
					result.Details = append(result.Details, fmt.Sprintf("Directory listing habilitado: %s", dir))
					result.Evidence = append(result.Evidence, Evidence{
						Type:     "Directory Listing",
						URL:      fullURL,
						Response: fmt.Sprintf("Directory listing enabled - found indicator: %s", indicator),
					})
					break
				}
			}
		}
	}
}

// CONF-03: Configuración incorrecta de servidor web
func (t *ConfigurationTest) testServerMisconfiguration(targetURL string, client HTTPClient, result *TestResult) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Verificar headers problemáticos
	problematicHeaders := map[string]string{
		"Server":           "Información del servidor expuesta",
		"X-Powered-By":     "Tecnología backend expuesta",
		"X-AspNet-Version": "Versión ASP.NET expuesta",
	}

	for header, issue := range problematicHeaders {
		if value := resp.Header.Get(header); value != "" {
			result.Details = append(result.Details, fmt.Sprintf("%s: %s (%s)", issue, value, header))
			result.Evidence = append(result.Evidence, Evidence{
				Type:     "Server Information Disclosure",
				URL:      targetURL,
				Response: fmt.Sprintf("%s: %s", header, value),
			})
		}
	}

	// Verificar métodos HTTP peligrosos
	dangerousMethods := []string{"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}

	for _, method := range dangerousMethods {
		req, err := http.NewRequest(method, targetURL, nil)
		if err != nil {
			continue
		}

		quickClient := &http.Client{Timeout: 5 * time.Second}
		resp, err := quickClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 405 && resp.StatusCode != 501 && resp.StatusCode != 429 {
			result.Details = append(result.Details, fmt.Sprintf("Método HTTP peligroso habilitado: %s (Status: %d)", method, resp.StatusCode))
			result.Evidence = append(result.Evidence, Evidence{
				Type:     "Dangerous HTTP Method",
				URL:      targetURL,
				Response: fmt.Sprintf("Method %s returned %d", method, resp.StatusCode),
			})
		}
	}
}

// CONF-04: Configuración errónea de CORS
func (t *ConfigurationTest) testCORSMisconfiguration(targetURL string, client HTTPClient, result *TestResult) {
	// Test con Origin malicioso
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}

	req.Header.Set("Origin", "https://evil.com")

	quickClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := quickClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Verificar headers CORS problemáticos

	accessControlOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	accessControlCredentials := resp.Header.Get("Access-Control-Allow-Credentials")

	// CORS wildcard con credentials
	if accessControlOrigin == "*" && strings.ToLower(accessControlCredentials) == "true" {
		result.Details = append(result.Details, "Configuración CORS peligrosa: wildcard (*) con credentials=true")
		result.Evidence = append(result.Evidence, Evidence{
			Type:     "CORS Misconfiguration",
			URL:      targetURL,
			Response: "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
		})
	}

	// Origin reflejado
	if accessControlOrigin == "https://evil.com" {
		result.Details = append(result.Details, "CORS mal configurado: Origin malicioso reflejado")
		result.Evidence = append(result.Evidence, Evidence{
			Type:     "CORS Origin Reflection",
			URL:      targetURL,
			Response: fmt.Sprintf("Malicious origin reflected: %s", accessControlOrigin),
		})
	}
}

// CONF-05: Rutas internas expuestas
func (t *ConfigurationTest) testInternalPaths(targetURL string, client HTTPClient, result *TestResult) {
	internalPaths := []string{
		"/debug",
		"/test",
		"/dev",
		"/development",
		"/staging",
		"/internal",
		"/private",
		"/admin",
		"/administrator",
		"/management",
		"/console",
		"/dashboard",
		"/panel",
		"/control",
		"/api/debug",
		"/api/test",
		"/api/internal",
		"/_debug",
		"/_test",
		"/_internal",
		"/health",
		"/status",
		"/metrics",
		"/actuator",
		"/actuator/health",
		"/actuator/info",
		"/actuator/env",
	}

	baseURL := strings.TrimSuffix(targetURL, "/")

	for _, path := range internalPaths {
		fullURL := baseURL + path

		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}

		quickClient := &http.Client{Timeout: 5 * time.Second}
		resp, err := quickClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Considerar accesible si no es 404, 403 o 429 (Rate Limit)
		if resp.StatusCode != 404 && resp.StatusCode != 403 && resp.StatusCode != 429 {
			result.Details = append(result.Details, fmt.Sprintf("Ruta interna accesible: %s (Status: %d)", path, resp.StatusCode))
			result.Evidence = append(result.Evidence, Evidence{
				Type:     "Internal Path Exposed",
				URL:      fullURL,
				Response: fmt.Sprintf("HTTP %d - Internal path accessible", resp.StatusCode),
			})
		}
	}
}

// DefaultPagesTest - CONF-06: Default Pages Detection
type DefaultPagesTest struct{}

func (t *DefaultPagesTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "CONF-06: Default Pages Detection",
		Description: "Detección de páginas por defecto del servidor web",
	}

	var details []string
	var evidence []Evidence

	// Páginas por defecto comunes
	defaultPages := []string{
		"/index.htm", "/index.html", "/default.htm", "/default.html",
		"/welcome.html", "/home.html", "/readme.html", "/test.html",
		"/phpinfo.php", "/info.php", "/server-info", "/server-status",
	}

	for _, page := range defaultPages {
		resp, err := client.Get(targetURL + page)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, err := ReadResponseBody(resp)
			if err == nil {
				// Buscar patrones de páginas por defecto
				if strings.Contains(strings.ToLower(body), "it works") ||
					strings.Contains(strings.ToLower(body), "apache") ||
					strings.Contains(strings.ToLower(body), "nginx") ||
					strings.Contains(strings.ToLower(body), "default") ||
					strings.Contains(strings.ToLower(body), "welcome") {

					details = append(details, fmt.Sprintf("Página por defecto encontrada: %s", page))
					evidence = append(evidence, Evidence{
						Type:        "Default Page",
						URL:         targetURL + page,
						StatusCode:  resp.StatusCode,
						Description: fmt.Sprintf("Página por defecto del servidor: %s", page),
						Severity:    "Low",
					})
				}
			}
		}
	}

	result.Details = details
	result.Evidence = evidence

	if len(evidence) == 0 {
		result.Status = "Passed"
		result.Severity = "Info"
	} else {
		result.Status = "Warning"
		result.Severity = "Low"
	}

	return result
}
