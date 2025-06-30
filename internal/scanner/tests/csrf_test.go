package tests

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// CSRFProtectionTest verifica la protección contra CSRF
type CSRFProtectionTest struct{}

// Run ejecuta el test de protección CSRF
func (c *CSRFProtectionTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName: "CSRF Protection",
		Status:   "Passed",
		Details:  []string{},
		Severity: "Medium",
	}

	// Hacer request GET para buscar formularios
	resp, err := client.Get(targetURL)
	if err != nil {
		result.Status = "Failed"
		result.Description = "Could not connect to target"
		result.Details = append(result.Details, fmt.Sprintf("Connection error: %v", err))
		return result
	}

	body := string(resp.Body)
	issues := []string{}
	warnings := []string{}

	// Buscar formularios en la página
	if strings.Contains(strings.ToLower(body), "<form") {
		// Verificar si hay tokens CSRF
		hasCSRFToken := strings.Contains(strings.ToLower(body), "csrf") ||
			strings.Contains(strings.ToLower(body), "_token") ||
			strings.Contains(strings.ToLower(body), "authenticity_token") ||
			strings.Contains(strings.ToLower(body), "csrfmiddlewaretoken")

		if !hasCSRFToken {
			issues = append(issues, "Formularios detectados sin tokens CSRF visibles")
			result.Severity = "High"
		} else {
			result.Details = append(result.Details, "✅ Tokens CSRF detectados en formularios")
		}

		// Verificar SameSite en cookies
		if resp.Headers != nil {
			cookies := resp.Headers.Get("Set-Cookie")
			if cookies != "" {
				if !strings.Contains(strings.ToLower(cookies), "samesite") {
					warnings = append(warnings, "Cookies sin atributo SameSite detectadas")
				} else {
					result.Details = append(result.Details, "✅ Atributo SameSite detectado en cookies")
				}
			}
		}
	} else {
		result.Details = append(result.Details, "ℹ️ No se detectaron formularios para analizar")
		result.Status = "Warning"
		result.Description = "No forms found to analyze"
	}

	// Verificar headers de seguridad relacionados con CSRF
	if resp.Headers != nil {
		// Verificar Referrer Policy
		referrerPolicy := resp.Headers.Get("Referrer-Policy")
		if referrerPolicy == "" {
			warnings = append(warnings, "Header Referrer-Policy no configurado")
		} else {
			result.Details = append(result.Details, fmt.Sprintf("✅ Referrer-Policy: %s", referrerPolicy))
		}

		// Verificar Origin headers
		origin := resp.Headers.Get("Access-Control-Allow-Origin")
		if origin == "*" {
			warnings = append(warnings, "CORS configurado para permitir cualquier origen")
		}
	}

	// Compilar resultado final
	if len(issues) > 0 {
		result.Status = "Failed"
		result.Description = "CSRF protection issues detected"
		result.Details = append(result.Details, "Problemas encontrados:")
		for _, issue := range issues {
			result.Details = append(result.Details, "  ❌ "+issue)
		}
	} else if len(warnings) > 0 {
		result.Status = "Warning"
		result.Description = "CSRF protection could be improved"
	} else {
		result.Description = "CSRF protection appears adequate"
	}

	if len(warnings) > 0 {
		result.Details = append(result.Details, "Advertencias:")
		for _, warning := range warnings {
			result.Details = append(result.Details, "  ⚠️ "+warning)
		}
	}

	return result
}
