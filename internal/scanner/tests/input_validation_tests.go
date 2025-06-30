package tests

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// InputValidationTest - Categoría INPV (INPV-01 a INPV-19)
type InputValidationTest struct{}

func (t *InputValidationTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "INPV-01: Input Validation Testing",
		Description: "Validación y saneamiento de entradas del usuario",
	}

	var details []string
	var evidence []Evidence

	// INPV-01: Pruebas de inyección SQL
	sqlPayloads := []string{
		"'", "''", "'OR'1'='1", "' OR 1=1--", "' OR 1=1#",
		"admin'--", "admin'#", "' UNION SELECT NULL--",
		"1'; DROP TABLE users--", "'; WAITFOR DELAY '00:00:10'--",
	}

	testEndpoints := []string{
		"/search", "/login", "/user", "/product", "/category",
		"/api/search", "/api/user", "/api/product",
	}

	for _, endpoint := range testEndpoints {
		for _, payload := range sqlPayloads {
			// Probar en parámetros GET
			testURL := targetURL + endpoint + "?id=" + url.QueryEscape(payload)
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			details = append(details, fmt.Sprintf("Probando SQL injection en %s con payload: %s (Status: %d)", endpoint, payload, resp.StatusCode))

			// Buscar indicadores de error SQL en la respuesta
			if resp.StatusCode == 500 {
				evidence = append(evidence, Evidence{
					Type:        "SQL Injection",
					URL:         testURL,
					Payload:     payload,
					StatusCode:  resp.StatusCode,
					Description: fmt.Sprintf("Posible vulnerabilidad de SQL injection en %s", endpoint),
					Severity:    "High",
				})
			}
		}
	}

	// INPV-02: Pruebas de Cross-Site Scripting (XSS)
	xssPayloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"';alert('XSS');//",
		"\"><script>alert('XSS')</script>",
		"<svg onload=alert(1)>",
	}

	for _, endpoint := range testEndpoints {
		for _, payload := range xssPayloads {
			testURL := targetURL + endpoint + "?q=" + url.QueryEscape(payload)
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			details = append(details, fmt.Sprintf("Probando XSS en %s con payload: %s (Status: %d)", endpoint, payload, resp.StatusCode))

			// En una implementación real, analizaríamos el contenido de la respuesta
			if resp.StatusCode == 200 {
				details = append(details, fmt.Sprintf("Respuesta 200 para XSS payload en %s", endpoint))
			}
		}
	}

	// INPV-03: Pruebas de Command Injection
	cmdPayloads := []string{
		"; ls", "| ls", "&& ls", "|| ls",
		"; cat /etc/passwd", "| cat /etc/passwd",
		"; dir", "| dir", "&& dir",
		"`ls`", "$(ls)", "${ls}",
	}

	for _, endpoint := range testEndpoints {
		for _, payload := range cmdPayloads {
			testURL := targetURL + endpoint + "?cmd=" + url.QueryEscape(payload)
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			details = append(details, fmt.Sprintf("Probando command injection en %s (Status: %d)", endpoint, resp.StatusCode))

			if resp.StatusCode == 500 {
				evidence = append(evidence, Evidence{
					Type:        "Command Injection",
					URL:         testURL,
					Payload:     payload,
					StatusCode:  resp.StatusCode,
					Description: fmt.Sprintf("Posible vulnerabilidad de command injection en %s", endpoint),
					Severity:    "Critical",
				})
			}
		}
	}

	// INPV-04: Pruebas de Path Traversal
	pathPayloads := []string{
		"../", "..\\", "....//", "....\\\\",
		"../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"%2e%2e%2f", "%2e%2e%5c", "%252e%252e%252f",
		"..%2F", "..%5C", "..%252F",
	}

	fileEndpoints := []string{
		"/file", "/download", "/image", "/document", "/attachment",
		"/api/file", "/api/download", "/static",
	}

	for _, endpoint := range fileEndpoints {
		for _, payload := range pathPayloads {
			testURL := targetURL + endpoint + "?file=" + url.QueryEscape(payload)
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			details = append(details, fmt.Sprintf("Probando path traversal en %s (Status: %d)", endpoint, resp.StatusCode))

			if resp.StatusCode == 200 {
				evidence = append(evidence, Evidence{
					Type:        "Path Traversal",
					URL:         testURL,
					Payload:     payload,
					StatusCode:  resp.StatusCode,
					Description: fmt.Sprintf("Posible vulnerabilidad de path traversal en %s", endpoint),
					Severity:    "High",
				})
			}
		}
	}

	result.Details = details
	result.Evidence = evidence

	if len(evidence) == 0 {
		result.Status = "Passed"
		result.Severity = "Info"
	} else {
		result.Status = "Failed"
		// Determinar severidad máxima
		maxSeverity := "Low"
		for _, ev := range evidence {
			if ev.Severity == "Critical" {
				maxSeverity = "Critical"
				break
			} else if ev.Severity == "High" && maxSeverity != "Critical" {
				maxSeverity = "High"
			} else if ev.Severity == "Medium" && maxSeverity != "High" && maxSeverity != "Critical" {
				maxSeverity = "Medium"
			}
		}
		result.Severity = maxSeverity
	}

	return result
}

// DataValidationTest - INPV-05: Data Validation
type DataValidationTest struct{}

func (t *DataValidationTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "INPV-05: Data Validation Testing",
		Description: "Pruebas de validación de tipos de datos y rangos",
	}

	var details []string
	var evidence []Evidence

	// Probar diferentes tipos de datos inválidos
	invalidDataTests := []struct {
		param    string
		values   []string
		expected string
	}{
		{"id", []string{"-1", "0", "999999", "abc", "null", "undefined"}, "numeric validation"},
		{"email", []string{"invalid", "@", "test@", "@domain.com", "test..test@domain.com"}, "email validation"},
		{"phone", []string{"abc", "123", "++123", "000000000000000"}, "phone validation"},
		{"date", []string{"invalid", "2023-13-01", "2023-02-30", "abc-01-01"}, "date validation"},
		{"amount", []string{"-100", "0.001", "999999999", "abc", "$100"}, "amount validation"},
	}

	testEndpoints := []string{"/search", "/user", "/product", "/api/user", "/api/product"}

	for _, endpoint := range testEndpoints {
		for _, test := range invalidDataTests {
			for _, value := range test.values {
				testURL := targetURL + endpoint + "?" + test.param + "=" + url.QueryEscape(value)
				resp, err := client.Get(testURL)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				details = append(details, fmt.Sprintf("Probando %s con %s=%s (Status: %d)", endpoint, test.param, value, resp.StatusCode))

				// Si devuelve 500, probablemente hay falta de validación
				if resp.StatusCode == 500 {
					evidence = append(evidence, Evidence{
						Type:        "Data Validation",
						URL:         testURL,
						Payload:     value,
						StatusCode:  resp.StatusCode,
						Description: fmt.Sprintf("Falta de validación de datos en %s para parámetro %s", endpoint, test.param),
						Severity:    "Medium",
					})
				}
			}
		}
	}

	// Probar tamaños de datos excesivos
	longString := strings.Repeat("A", 10000)
	lengthTests := []string{
		"name=" + url.QueryEscape(longString),
		"description=" + url.QueryEscape(longString),
		"comment=" + url.QueryEscape(longString),
	}

	for _, endpoint := range testEndpoints {
		for _, test := range lengthTests {
			testURL := targetURL + endpoint + "?" + test
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			details = append(details, fmt.Sprintf("Probando longitud excesiva en %s (Status: %d)", endpoint, resp.StatusCode))

			if resp.StatusCode == 500 || resp.StatusCode == 413 {
				evidence = append(evidence, Evidence{
					Type:        "Length Validation",
					URL:         testURL,
					StatusCode:  resp.StatusCode,
					Description: fmt.Sprintf("Manejo inadecuado de datos de longitud excesiva en %s", endpoint),
					Severity:    "Low",
				})
			}
		}
	}

	result.Details = details
	result.Evidence = evidence

	if len(evidence) == 0 {
		result.Status = "Passed"
		result.Severity = "Info"
	} else {
		result.Status = "Failed"
		// Determinar severidad máxima
		maxSeverity := "Low"
		for _, ev := range evidence {
			if ev.Severity == "Medium" && maxSeverity != "High" {
				maxSeverity = "Medium"
			}
		}
		result.Severity = maxSeverity
	}

	return result
}
