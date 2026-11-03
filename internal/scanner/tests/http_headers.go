package tests

import (
	"fmt"
	"strings"

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

	// Headers que SÍ deben estar. HSTS solo tiene sentido sobre HTTPS (un sitio HTTP no puede fijarlo),
	// así que no se exige en HTTP. X-XSS-Protection está obsoleto (los navegadores lo quitaron): su
	// ausencia es solo informativa, no una falla.
	isHTTPS := strings.HasPrefix(strings.ToLower(targetURL), "https://")
	required := []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"}
	if isHTTPS {
		required = append(required, "Strict-Transport-Security")
	}

	for _, header := range required {
		if resp.Header.Get(header) == "" {
			result.Status = "Failed"
			result.Details = append(result.Details, "❌ "+header+" ausente")
		} else {
			result.Details = append(result.Details, "✅ "+header+" presente")
		}
	}
	if !isHTTPS {
		result.Details = append(result.Details, "ℹ️ HSTS no se evalúa: solo aplica sobre HTTPS")
	}
	if resp.Header.Get("X-XSS-Protection") == "" {
		result.Details = append(result.Details, "ℹ️ X-XSS-Protection ausente (obsoleto; no es una falla)")
	}

	if result.Status == "Passed" {
		result.Description = "All security headers are present"
	} else {
		result.Description = "Some security headers are missing"
	}

	return result
}
