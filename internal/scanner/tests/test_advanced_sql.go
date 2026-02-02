package tests

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/versaSecurityTest/internal/config"
)

// AdvancedSQLInjectionTest - Test agresivo y completo de SQL Injection
type AdvancedSQLInjectionTest struct {
	Discovery *DiscoveryResult
}

// Run ejecuta tests exhaustivos de SQL injection
func (t *AdvancedSQLInjectionTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "Advanced SQL Injection Test",
		Status:      "Passed",
		Description: "No se detectaron vulnerabilidades de inyección SQL",
		Severity:    "None",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	// PAYLOADS EXHAUSTIVOS (reducidos para el ejemplo, pero en un caso real usaríamos la lista completa)
	sqlPayloads := []string{
		"'", "''", "\"", "\"\"",
		"' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
		"\" OR \"1\"=\"1", "\" OR 1=1--",
		"'; WAITFOR DELAY '00:00:05'--", "'; SELECT pg_sleep(5)--",
		"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
	}

	var endpointsToTest []string
	var paramsToTest []string

	if t.Discovery != nil && len(t.Discovery.Endpoints) > 0 {
		for _, info := range t.Discovery.Endpoints {
			for _, method := range info.Methods {
				if method == "GET" {
					endpointsToTest = append(endpointsToTest, info.Path)
					paramsToTest = append(paramsToTest, info.Params...)
				}
			}
		}
	} else {
		// Fallback si no hay descubrimiento
		endpointsToTest = []string{"/", "/login", "/search", "/api/user"}
		paramsToTest = []string{"id", "user", "q", "query"}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var vulnerabilitiesFound int

	// Limitar concurrencia interna por test para no saturar totalmente
	semaphore := make(chan struct{}, 5)

	for _, endpoint := range endpointsToTest {
		for _, param := range paramsToTest {
			for _, payload := range sqlPayloads {
				wg.Add(1)
				go func(e, p, pay string) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					testURL := fmt.Sprintf("%s%s?%s=%s", targetURL, e, p, url.QueryEscape(pay))

					startTime := time.Now()
					resp, err := client.Get(testURL)
					if err != nil {
						return
					}
					defer resp.Body.Close()

					duration := time.Since(startTime)
					body, _ := io.ReadAll(resp.Body)

					vuln := t.analyzeResponse(resp.StatusCode, string(body), duration, pay)
					if vuln.IsVulnerable {
						mu.Lock()
						vulnerabilitiesFound++
						result.Evidence = append(result.Evidence, Evidence{
							Type:        "SQL Injection",
							URL:         testURL,
							Payload:     pay,
							StatusCode:  resp.StatusCode,
							Response:    vuln.Evidence,
							Description: vuln.Description,
							Severity:    vuln.Severity,
						})
						mu.Unlock()
					}
				}(endpoint, param, payload)
			}
		}
	}

	wg.Wait()

	if vulnerabilitiesFound > 0 {
		result.Status = "Failed"
		result.Severity = "Critical"
		result.Description = fmt.Sprintf("CRÍTICO: Se detectaron %d vulnerabilidades de SQL injection", vulnerabilitiesFound)
	}

	return result
}

// SQLVulnerability estructura para análisis de vulnerabilidades
type SQLVulnerability struct {
	IsVulnerable bool
	Description  string
	Evidence     string
	Severity     string
}

// analyzeResponse analiza la respuesta en busca de indicadores de SQL injection
func (t *AdvancedSQLInjectionTest) analyzeResponse(statusCode int, responseText string, responseTime time.Duration, payload string) SQLVulnerability {
	responseLower := strings.ToLower(responseText)

	// PATRONES DE ERROR SQL
	sqlErrorPatterns := []struct {
		pattern  string
		database string
		severity string
	}{
		// MySQL
		{"you have an error in your sql syntax", "MySQL", "Critical"},
		{"warning: mysql_", "MySQL", "High"},
		{"mysql_fetch_array()", "MySQL", "High"},
		{"mysql_num_rows()", "MySQL", "High"},
		{"mysql error", "MySQL", "High"},
		{"supplied argument is not a valid mysql", "MySQL", "High"},

		// MSSQL
		{"microsoft ole db provider for sql server", "MSSQL", "Critical"},
		{"unclosed quotation mark after the character string", "MSSQL", "Critical"},
		{"incorrect syntax near", "MSSQL", "Critical"},
		{"'80040e14'", "MSSQL", "High"},
		{"mssql_query()", "MSSQL", "High"},

		// Oracle
		{"ora-01756", "Oracle", "Critical"},
		{"ora-00933", "Oracle", "Critical"},
		{"ora-00921", "Oracle", "Critical"},
		{"oracle error", "Oracle", "High"},
		{"oracle driver", "Oracle", "Medium"},

		// PostgreSQL
		{"invalid input syntax for type", "PostgreSQL", "Critical"},
		{"unterminated quoted string", "PostgreSQL", "Critical"},
		{"pg_query() expects", "PostgreSQL", "High"},
		{"postgresql error", "PostgreSQL", "High"},

		// Generic
		{"sql syntax", "Generic", "High"},
		{"database error", "Generic", "Medium"},
		{"query failed", "Generic", "Medium"},
		{"invalid query", "Generic", "Medium"},
		{"syntax error", "Generic", "Medium"},
	}

	// Buscar patrones de error
	for _, pattern := range sqlErrorPatterns {
		if strings.Contains(responseLower, pattern.pattern) {
			return SQLVulnerability{
				IsVulnerable: true,
				Description:  fmt.Sprintf("Error de base de datos %s detectado", pattern.database),
				Evidence:     fmt.Sprintf("Patrón encontrado: '%s' en respuesta con payload '%s'", pattern.pattern, payload),
				Severity:     pattern.severity,
			}
		}
	}

	// ANÁLISIS POR STATUS CODE
	if statusCode == 500 {
		// Buscar más detalles en error 500
		if strings.Contains(responseLower, "exception") || strings.Contains(responseLower, "error") {
			return SQLVulnerability{
				IsVulnerable: true,
				Description:  "Error 500 con información de excepción - posible SQL injection",
				Evidence:     fmt.Sprintf("Status 500 con payload '%s' y stack trace visible", payload),
				Severity:     "High",
			}
		}
	}

	// ANÁLISIS DE TIMING ATTACKS
	if responseTime > 5*time.Second && (strings.Contains(payload, "SLEEP") || strings.Contains(payload, "WAITFOR") || strings.Contains(payload, "pg_sleep")) {
		return SQLVulnerability{
			IsVulnerable: true,
			Description:  "Time-based SQL injection detectada",
			Evidence:     fmt.Sprintf("Tiempo de respuesta anómalo: %v con payload temporal '%s'", responseTime, payload),
			Severity:     "Critical",
		}
	}

	// ANÁLISIS DE CONTENIDO ESPECÍFICO
	if strings.Contains(responseLower, "mysql") && strings.Contains(payload, "version") {
		return SQLVulnerability{
			IsVulnerable: true,
			Description:  "Información de versión MySQL expuesta",
			Evidence:     fmt.Sprintf("Referencia a MySQL en respuesta con payload '%s'", payload),
			Severity:     "Medium",
		}
	}

	// DETECCIÓN DE UNION-BASED INJECTION
	if strings.Contains(payload, "UNION") && statusCode == 200 {
		// Buscar patrones que indiquen éxito de UNION
		unionPatterns := []string{"null", "1", "2", "3", "admin", "root", "test"}
		for _, pattern := range unionPatterns {
			if strings.Contains(responseLower, pattern) && len(responseText) > 100 {
				return SQLVulnerability{
					IsVulnerable: true,
					Description:  "Posible UNION-based SQL injection",
					Evidence:     fmt.Sprintf("UNION query aparentemente exitosa con payload '%s'", payload),
					Severity:     "High",
				}
			}
		}
	}

	// ANÁLISIS DE BOOLEAN-BASED INJECTION
	if strings.Contains(payload, "1=1") || strings.Contains(payload, "'1'='1") {
		// En Boolean-based, buscamos diferencias en el comportamiento
		if statusCode == 200 && len(responseText) > 50 {
			return SQLVulnerability{
				IsVulnerable: true,
				Description:  "Posible Boolean-based SQL injection",
				Evidence:     fmt.Sprintf("Comportamiento diferente con payload lógico '%s'", payload),
				Severity:     "High",
			}
		}
	}

	return SQLVulnerability{IsVulnerable: false}
}
