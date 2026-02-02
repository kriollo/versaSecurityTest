package tests

import (
	"fmt"
	"io"
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
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Status = "Failed"
		result.Description = "Could not read response body"
		result.Details = append(result.Details, fmt.Sprintf("Read error: %v", err))
		return result
	}
	body := string(bodyBytes)
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
		if resp.Header != nil {
			cookies := resp.Header.Get("Set-Cookie")
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

	// Verificar headers de seguridad relacionados con CSRF (Análisis profundo)
	if resp.Header != nil {
		// 1. Referrer-Policy: CRÍTICO para CSRF
		referrerPolicy := resp.Header.Get("Referrer-Policy")
		if referrerPolicy == "" {
			issues = append(issues, "Header Referrer-Policy no configurado (pérdida potencial de control sobre referrers)")
		} else {
			loweredPolicy := strings.ToLower(referrerPolicy)
			if loweredPolicy == "unsafe-url" || loweredPolicy == "no-referrer-when-downgrade" {
				issues = append(issues, fmt.Sprintf("Referrer-Policy inseguro detectado: %s", referrerPolicy))
				result.Severity = "Medium"
			} else {
				result.Details = append(result.Details, fmt.Sprintf("✅ Referrer-Policy robusto: %s", referrerPolicy))
			}
		}

		// 2. SameSite en cookies (Verificar todas)
		setCookies := resp.Header["Set-Cookie"]
		if len(setCookies) > 0 {
			for _, cookie := range setCookies {
				cookieLower := strings.ToLower(cookie)
				if !strings.Contains(cookieLower, "samesite=strict") && !strings.Contains(cookieLower, "samesite=lax") {
					warnings = append(warnings, fmt.Sprintf("Cookie detectada sin SameSite=Strict/Lax: %s", strings.Split(cookie, ";")[0]))
				}
			}
		}

		// 3. CSP frame-ancestors (Protección contra Clickjacking/CSRF multi-vector)
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
			warnings = append(warnings, "CSP no define directiva 'frame-ancestors' (capa extra de defensa ausente)")
		}

		// 4. CORS Mal configurado
		origin := resp.Header.Get("Access-Control-Allow-Origin")
		if origin == "*" {
			issues = append(issues, "CORS configurado con '*' (permite cualquier origen)")
			result.Severity = "High"
		}
	}

	// 5. Análisis de formularios y Tokens
	if strings.Contains(strings.ToLower(body), "<form") {
		// Lista expandida de patrones de tokens
		csrfPatterns := []string{"csrf", "_token", "authenticity_token", "csrfmiddlewaretoken", "xsrf"}
		foundToken := false
		for _, pattern := range csrfPatterns {
			if strings.Contains(strings.ToLower(body), pattern) {
				foundToken = true
				break
			}
		}

		if !foundToken {
			issues = append(issues, "Formulario detectado sin token anti-CSRF aparente")
			result.Severity = "High"
		}
	}

	// Compilar resultado final
	if len(issues) > 0 {
		result.Status = "Failed"
		result.Description = "Se detectaron debilidades en la protección CSRF"
		for _, issue := range issues {
			result.Details = append(result.Details, "  ❌ "+issue)
		}
	} else if len(warnings) > 0 {
		result.Status = "Warning"
		result.Description = "La protección CSRF puede mejorarse"
	}

	if len(warnings) > 0 {
		for _, warning := range warnings {
			result.Details = append(result.Details, "  ⚠️ "+warning)
		}
	}

	return result
}
