package tests

import (
	"fmt"
	"io"
	"net/http"
	"strings"
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
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity,omitempty"`
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

	// Lista de payloads SQL a probar
	sqlPayloads := []string{
		"1'",
		"' OR '1'='1",
		"' UNION SELECT null--",
		"1' AND 1=1--",
		"'; DROP TABLE users--",
	}

	var detectedVulns int
	for _, payload := range sqlPayloads {
		testURL := targetURL + "?id=" + payload
		
		resp, err := client.Get(testURL)
		if err != nil {
			// Si hay error de conexión, continuar con el siguiente payload
			continue
		}
		defer resp.Body.Close()

		// Leer la respuesta del servidor
		body, _ := io.ReadAll(resp.Body)
		responseText := string(body)
		
		// Detectar signos de inyección SQL
		vulnDetected := false
		vulnReason := ""
		
		if resp.StatusCode == 500 {
			vulnDetected = true
			vulnReason = "Error 500 del servidor"
		} else if strings.Contains(strings.ToLower(responseText), "sql") {
			vulnDetected = true
			vulnReason = "Mensaje de error SQL en la respuesta"
		} else if strings.Contains(strings.ToLower(responseText), "mysql") {
			vulnDetected = true
			vulnReason = "Referencia a MySQL en la respuesta"
		} else if strings.Contains(strings.ToLower(responseText), "syntax error") {
			vulnDetected = true
			vulnReason = "Error de sintaxis detectado"
		}
		
		if vulnDetected {
			detectedVulns++
			
			// Truncar respuesta para mostrar solo los primeros caracteres
			truncatedResponse := responseText
			if len(truncatedResponse) > 200 {
				truncatedResponse = truncatedResponse[:200] + "..."
			}
			
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "SQL Injection",
				URL:         testURL,
				Payload:     payload,
				StatusCode:  resp.StatusCode,
				Response:    fmt.Sprintf("%s: %s", vulnReason, truncatedResponse),
				Description: fmt.Sprintf("Payload '%s' causó comportamiento anormal", payload),
				Severity:    "High",
			})
			
			result.Details = append(result.Details, 
				fmt.Sprintf("Payload '%s': %s (Status: %d)", payload, vulnReason, resp.StatusCode))
		}
	}

	// Evaluar resultados
	if detectedVulns > 0 {
		result.Status = "Failed"
		result.Severity = "High"
		result.Description = fmt.Sprintf("Se detectaron %d posibles vulnerabilidades de inyección SQL", detectedVulns)
	} else {
		result.Details = append(result.Details, "Todos los payloads SQL probados no mostraron signos de vulnerabilidad")
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

	// Lista de payloads XSS a probar
	xssPayloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"javascript:alert('XSS')",
		"'><script>alert('XSS')</script>",
	}
	
	var detectedVulns int
	for _, payload := range xssPayloads {
		testURL := targetURL + "?q=" + payload
		
		resp, err := client.Get(testURL)
		if err != nil {
			// Si hay error de conexión, continuar con el siguiente payload
			continue
		}
		defer resp.Body.Close()

		// Leer la respuesta del servidor
		body, _ := io.ReadAll(resp.Body)
		responseText := string(body)
		
		// Detectar signos de XSS (script reflejado sin sanitización)
		vulnDetected := false
		vulnReason := ""
		
		// Verificar si el payload se refleja sin codificar
		if strings.Contains(responseText, "<script>") {
			vulnDetected = true
			vulnReason = "Script tag reflejado sin sanitización"
		} else if strings.Contains(responseText, "onerror=") {
			vulnDetected = true
			vulnReason = "Atributo onerror reflejado"
		} else if strings.Contains(responseText, "onload=") {
			vulnDetected = true
			vulnReason = "Atributo onload reflejado"
		} else if strings.Contains(responseText, "javascript:") {
			vulnDetected = true
			vulnReason = "URL javascript: reflejada"
		}
		
		if vulnDetected {
			detectedVulns++
			
			// Truncar respuesta para mostrar solo los primeros caracteres
			truncatedResponse := responseText
			if len(truncatedResponse) > 300 {
				truncatedResponse = truncatedResponse[:300] + "..."
			}
			
			// Buscar la línea específica donde aparece el payload
			lines := strings.Split(responseText, "\n")
			reflectedLine := ""
			for _, line := range lines {
				if strings.Contains(line, payload) || strings.Contains(line, "<script") {
					reflectedLine = strings.TrimSpace(line)
					if len(reflectedLine) > 150 {
						reflectedLine = reflectedLine[:150] + "..."
					}
					break
				}
			}
			
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "Cross-Site Scripting",
				URL:         testURL,
				Payload:     payload,
				StatusCode:  resp.StatusCode,
				Response:    fmt.Sprintf("%s. Línea afectada: %s", vulnReason, reflectedLine),
			})
			
			result.Details = append(result.Details, 
				fmt.Sprintf("Payload '%s': %s (Status: %d)", payload, vulnReason, resp.StatusCode))
		}
	}

	// Evaluar resultados
	if detectedVulns > 0 {
		result.Status = "Failed"
		result.Severity = "High"
		result.Description = fmt.Sprintf("Se detectaron %d posibles vulnerabilidades XSS", detectedVulns)
	} else {
		result.Details = append(result.Details, "Todos los payloads XSS probados fueron correctamente sanitizados")
	}

	return result
}
