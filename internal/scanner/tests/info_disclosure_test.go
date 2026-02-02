package tests

import (
	"fmt"
	"io"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// InfoDisclosureTest detecta divulgación de información sensible
type InfoDisclosureTest struct{}

// Run ejecuta el test de divulgación de información
func (i *InfoDisclosureTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName: "Information Disclosure",
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

	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		result.Status = "Failed"
		result.Description = "Error reading response body"
		return result
	}
	body := string(bodyBytes)
	bodyLower := strings.ToLower(body)

	// Patrones de información sensible
	patterns := map[string]string{
		"password":  "Password field or text found",
		"username":  "Username field or text found",
		"admin":     "Admin references found",
		"database":  "Database references found",
		"error":     "Error messages found",
		"exception": "Exception information found",
		"debug":     "Debug information found",
		"config":    "Configuration information found",
		"api_key":   "API key references found",
		"secret":    "Secret references found",
	}

	foundIssues := 0
	for pattern, description := range patterns {
		if strings.Contains(bodyLower, pattern) {
			result.Details = append(result.Details, "⚠️ "+description)
			foundIssues++
		}
	}

	// Verificar headers que pueden revelar información
	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" {
		result.Details = append(result.Details, fmt.Sprintf("ℹ️ Server header: %s", serverHeader))
	}

	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		result.Details = append(result.Details, fmt.Sprintf("⚠️ X-Powered-By header reveals: %s", poweredBy))
		foundIssues++
	}

	if foundIssues > 3 {
		result.Status = "Failed"
		result.Description = "Significant information disclosure detected"
		result.Severity = "High"
	} else if foundIssues > 0 {
		result.Status = "Warning"
		result.Description = "Some information disclosure detected"
	} else {
		result.Description = "No obvious information disclosure detected"
	}

	return result
}
