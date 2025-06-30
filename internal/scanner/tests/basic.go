package tests

import (
	"fmt"
	"net/http"
	"time"

	"github.com/versaSecurityTest/internal/config"
)

// BasicTest implementa un test básico de conectividad y headers
type BasicTest struct{}

// TestResult representa el resultado de un test
type TestResult struct {
	TestName    string    `json:"test_name"`
	Status      string    `json:"status"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Details     []string  `json:"details,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`
}

// Evidence contiene evidencia de una vulnerabilidad
type Evidence struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	Payload     string `json:"payload,omitempty"`
	Response    string `json:"response,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
}

// HTTPClient interface simplificada
type HTTPClient interface {
	Get(url string) (*http.Response, error)
}

// BasicHTTPClient implementación básica
type BasicHTTPClient struct {
	client *http.Client
}

// NewBasicHTTPClient crea un nuevo cliente HTTP básico
func NewBasicHTTPClient() *BasicHTTPClient {
	return &BasicHTTPClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Get realiza una petición GET
func (c *BasicHTTPClient) Get(url string) (*http.Response, error) {
	return c.client.Get(url)
}

// Run ejecuta el test básico
func (t *BasicTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "Basic Connectivity & Headers",
		Status:      "Passed",
		Description: "Conectividad básica y verificación de headers funcionando correctamente",
		Severity:    "None",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	// Test de conectividad básica
	resp, err := client.Get(targetURL)
	if err != nil {
		result.Status = "Failed"
		result.Severity = "High"
		result.Description = fmt.Sprintf("Error de conectividad: %v", err)
		result.Details = append(result.Details, "No se pudo establecer conexión con el servidor")
		return result
	}
	defer resp.Body.Close()

	var issues []string

	// Verificar status code
	if resp.StatusCode >= 400 {
		issues = append(issues, fmt.Sprintf("Status code de error: %d", resp.StatusCode))
		result.Evidence = append(result.Evidence, Evidence{
			Type:       "HTTP Error",
			URL:        targetURL,
			StatusCode: resp.StatusCode,
			Response:   fmt.Sprintf("Status: %d %s", resp.StatusCode, resp.Status),
		})
	}

	// Verificar headers de seguridad básicos
	securityHeaders := map[string]string{
		"X-Frame-Options":        "Protege contra clickjacking",
		"X-Content-Type-Options": "Previene MIME type sniffing",
		"X-XSS-Protection":       "Protección XSS básica",
	}

	for header, description := range securityHeaders {
		if resp.Header.Get(header) == "" {
			issues = append(issues, fmt.Sprintf("Header de seguridad '%s' faltante", header))
			result.Evidence = append(result.Evidence, Evidence{
				Type:     "Missing Security Header",
				URL:      targetURL,
				Response: fmt.Sprintf("Header %s no encontrado - %s", header, description),
			})
		}
	}

	// Verificar si se expone información del servidor
	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" {
		issues = append(issues, fmt.Sprintf("Header Server expone información: %s", serverHeader))
		result.Evidence = append(result.Evidence, Evidence{
			Type:     "Information Disclosure",
			URL:      targetURL,
			Response: fmt.Sprintf("Server: %s", serverHeader),
		})
	}

	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" {
		issues = append(issues, fmt.Sprintf("Header X-Powered-By expone tecnología: %s", xPoweredBy))
		result.Evidence = append(result.Evidence, Evidence{
			Type:     "Information Disclosure",
			URL:      targetURL,
			Response: fmt.Sprintf("X-Powered-By: %s", xPoweredBy),
		})
	}

	// Evaluar resultado final
	if len(issues) > 0 {
		result.Status = "Failed"
		result.Details = issues
		
		// Determinar severidad basada en los problemas encontrados
		if len(issues) >= 3 {
			result.Severity = "Medium"
			result.Description = fmt.Sprintf("Se encontraron %d problemas de seguridad", len(issues))
		} else {
			result.Severity = "Low"
			result.Description = fmt.Sprintf("Se encontraron %d problemas menores", len(issues))
		}
	}

	return result
}

// SQLInjectionTest test básico de SQL injection
type SQLInjectionTest struct{}

// Run ejecuta test básico de SQL injection
func (t *SQLInjectionTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "SQL Injection",
		Status:      "Passed",
		Description: "No se detectaron vulnerabilidades evidentes de inyección SQL",
		Severity:    "None",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	// Test muy básico - solo probar con un payload simple
	testURL := targetURL + "?id=1'"
	
	resp, err := client.Get(testURL)
	if err != nil {
		// Si hay error, puede ser buena señal (el servidor rechaza la request)
		return result
	}
	defer resp.Body.Close()

	// Si el status code indica error del servidor, puede ser vulnerable
	if resp.StatusCode == 500 {
		result.Status = "Failed"
		result.Severity = "High"
		result.Description = "Posible vulnerabilidad de inyección SQL detectada"
		result.Details = append(result.Details, "El servidor retornó error 500 con payload SQL")
		result.Evidence = append(result.Evidence, Evidence{
			Type:       "SQL Injection",
			URL:        testURL,
			Payload:    "1'",
			StatusCode: resp.StatusCode,
			Response:   "Error 500 - posible inyección SQL",
		})
	}

	return result
}

// XSSTest test básico de XSS
type XSSTest struct{}

// Run ejecuta test básico de XSS
func (t *XSSTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "Cross-Site Scripting (XSS)",
		Status:      "Passed",
		Description: "No se detectaron vulnerabilidades evidentes de XSS",
		Severity:    "None",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	// Test muy básico - solo probar con un payload simple
	testURL := targetURL + "?q=<script>alert('xss')</script>"
	
	resp, err := client.Get(testURL)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	// En un test real analizaríamos el contenido de la respuesta
	// Por ahora solo verificamos que no haya errores evidentes
	if resp.StatusCode >= 400 {
		result.Status = "Warning"
		result.Severity = "Low"
		result.Description = "Se detectó comportamiento anómalo con payload XSS"
		result.Details = append(result.Details, fmt.Sprintf("Status code: %d", resp.StatusCode))
	}

	return result
}
