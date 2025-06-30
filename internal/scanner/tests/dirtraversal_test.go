package tests

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// DirTraversalTest detecta vulnerabilidades de directory traversal
type DirTraversalTest struct{}

// Run ejecuta el test de directory traversal
func (d *DirTraversalTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName: "Directory Traversal",
		Status:   "Passed",
		Details:  []string{},
		Severity: "High",
	}

	// Payloads comunes para directory traversal
	traversalPayloads := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
	}

	vulnerableParams := 0
	totalTests := 0

	// Buscar parámetros que puedan ser vulnerables
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Status = "Failed"
		result.Description = "Invalid URL provided"
		result.Details = append(result.Details, fmt.Sprintf("URL parsing error: %v", err))
		return result
	}

	// Parámetros comunes que suelen ser vulnerables
	commonParams := []string{"file", "page", "include", "document", "path", "dir", "folder"}

	for _, param := range commonParams {
		for _, payload := range traversalPayloads {
			totalTests++
			
			// Construir URL de prueba
			testURL := fmt.Sprintf("%s?%s=%s", targetURL, param, url.QueryEscape(payload))
			
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}

			body := string(resp.Body)
			bodyLower := strings.ToLower(body)

			// Buscar indicadores de éxito en directory traversal
			if strings.Contains(bodyLower, "root:") ||
				strings.Contains(bodyLower, "# localhost") ||
				strings.Contains(bodyLower, "[boot loader]") ||
				strings.Contains(bodyLower, "# this file contains") {
				
				vulnerableParams++
				result.Status = "Failed"
				result.Details = append(result.Details, fmt.Sprintf("❌ Vulnerable parameter detected: %s", param))
				result.Details = append(result.Details, fmt.Sprintf("   Payload: %s", payload))
				break // Una vez encontrada vulnerabilidad, no necesitamos más payloads para este parámetro
			}
		}
	}

	// Probar paths comunes que pueden ser vulnerables
	pathTests := []string{
		"/download?file=../../../etc/passwd",
		"/view?page=../../../windows/system32/drivers/etc/hosts",
		"/include?document=....//....//etc/passwd",
	}

	for _, pathTest := range pathTests {
		totalTests++
		testURL := targetURL + pathTest
		
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}

		body := string(resp.Body)
		if strings.Contains(strings.ToLower(body), "root:") {
			vulnerableParams++
			result.Status = "Failed"
			result.Details = append(result.Details, fmt.Sprintf("❌ Vulnerable path: %s", pathTest))
		}
	}

	result.Details = append(result.Details, fmt.Sprintf("📊 Total tests performed: %d", totalTests))

	if result.Status == "Failed" {
		result.Description = fmt.Sprintf("Directory traversal vulnerability detected (%d vulnerable parameters)", vulnerableParams)
		result.Severity = "Critical"
	} else {
		result.Description = "No directory traversal vulnerabilities detected"
		result.Details = append(result.Details, "✅ No se detectaron vulnerabilidades de directory traversal")
	}

	return result
}
