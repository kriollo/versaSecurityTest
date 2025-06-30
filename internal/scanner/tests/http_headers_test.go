package tests

import (
	"fmt"
	"net/http"

	"github.com/versaSecurityTest/internal/config"
)

// HTTPHeadersTest verifica la presencia de headers de seguridad
type HTTPHeadersTest struct{}

// Run ejecuta el test de headers HTTP
func (h *HTTPHeadersTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName: "HTTP Headers Test",
		Status:   "Passed",
		Details:  []string{},
		Severity: "Medium",
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		result.Status = "Failed"
		result.Description = "Could not connect to target"
		result.Details = append(result.Details, fmt.Sprintf("Connection error: %v", err))
		return result
	}

	// Lista de headers críticos
	headers := map[string]string{
		"Content-Security-Policy": "Content-Security-Policy not found",
		"Strict-Transport-Security": "Strict-Transport-Security not found",
		"X-Content-Type-Options": "X-Content-Type-Options not set",
		"X-Frame-Options": "X-Frame-Options not set",
		"X-XSS-Protection": "X-Content-Type-Options not set",
	}

	for header, desc := range headers {
		if resp.Headers.Get(header) == "" {
			result.Status = "Failed"
			result.Details = append(result.Details, "❌ "+desc)
		} else {
			result.Details = append(result.Details, "✅ "+header+" found")
		}
	}

	if result.Status == "Passed" {
		result.Description = "All security headers are present"
	} else {
		result.Description = "Some security headers are missing"
	}

	return result
}

