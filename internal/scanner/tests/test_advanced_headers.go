package tests

import (
	"fmt"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// AdvancedSecurityHeadersTest - Test exhaustivo de headers de seguridad
type AdvancedSecurityHeadersTest struct{}

// Run ejecuta tests completos de headers de seguridad
func (t *AdvancedSecurityHeadersTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "Advanced Security Headers Test",
		Status:      "Passed",
		Description: "Headers de seguridad correctamente configurados",
		Severity:    "None",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		result.Status = "Failed"
		result.Severity = "High"
		result.Description = "No se pudo conectar al servidor"
		result.Details = append(result.Details, fmt.Sprintf("Error de conexión: %v", err))
		return result
	}
	defer resp.Body.Close()

	var issues []string
	var warnings []string
	var critical []string

	// HEADERS CRÍTICOS DE SEGURIDAD
	securityHeaders := map[string]HeaderCheck{
		"Content-Security-Policy": {
			Required:      true,
			Severity:      "Critical",
			Description:   "Previene XSS y data injection attacks",
			ValidValues:   []string{"default-src", "script-src", "style-src"},
			InvalidValues: []string{"unsafe-inline", "unsafe-eval", "*"},
		},
		"Strict-Transport-Security": {
			Required:      true,
			Severity:      "High",
			Description:   "Fuerza conexiones HTTPS",
			ValidValues:   []string{"max-age=", "includeSubDomains"},
			InvalidValues: []string{"max-age=0"},
		},
		"X-Frame-Options": {
			Required:      true,
			Severity:      "High",
			Description:   "Previene clickjacking",
			ValidValues:   []string{"DENY", "SAMEORIGIN"},
			InvalidValues: []string{"ALLOW-FROM"},
		},
		"X-Content-Type-Options": {
			Required:      true,
			Severity:      "Medium",
			Description:   "Previene MIME type sniffing",
			ValidValues:   []string{"nosniff"},
			InvalidValues: []string{},
		},
		"X-XSS-Protection": {
			Required:      false, // Deprecado pero aún útil
			Severity:      "Low",
			Description:   "Protección XSS legacy para navegadores antiguos",
			ValidValues:   []string{"1; mode=block"},
			InvalidValues: []string{"0"},
		},
		"Referrer-Policy": {
			Required:      true,
			Severity:      "Medium",
			Description:   "Controla información en header Referer",
			ValidValues:   []string{"strict-origin-when-cross-origin", "strict-origin", "no-referrer"},
			InvalidValues: []string{"unsafe-url", "no-referrer-when-downgrade"},
		},
		"Permissions-Policy": {
			Required:      false,
			Severity:      "Low",
			Description:   "Controla características del navegador (cámara, micro, etc.)",
			ValidValues:   []string{"geolocation=", "camera=", "microphone="},
			InvalidValues: []string{"*"},
		},
		"Cross-Origin-Embedder-Policy": {
			Required:      false,
			Severity:      "Low",
			Description:   "Previene que el documento cargue recursos cross-origin sin permiso",
			ValidValues:   []string{"require-corp", "credentialless"},
			InvalidValues: []string{},
		},
		"Cross-Origin-Opener-Policy": {
			Required:      false,
			Severity:      "Low",
			Description:   "Aísla el contexto de navegación de otros documentos",
			ValidValues:   []string{"same-origin", "same-origin-allow-popups"},
			InvalidValues: []string{"unsafe-none"},
		},
		"Expect-CT": {
			Required:      false, // Deprecado pero aún visible en algunos reportes
			Severity:      "Low",
			Description:   "Certificate Transparency enforcement",
			ValidValues:   []string{"max-age=", "enforce"},
			InvalidValues: []string{},
		},
	}

	// Verificar cada header
	isHTTPS := strings.HasPrefix(strings.ToLower(targetURL), "https://")
	for headerName, check := range securityHeaders {
		headerValue := resp.Header.Get(headerName)

		// HSTS solo tiene sentido sobre HTTPS; en HTTP se recomienda migrar a HTTPS,
		// no reportar el header como ausente (falso positivo).
		if headerName == "Strict-Transport-Security" && !isHTTPS {
			warnings = append(warnings, "ℹ️  HSTS no aplica: el sitio usa HTTP (migrar a HTTPS)")
			continue
		}

		if headerValue == "" {
			if check.Required {
				if check.Severity == "Critical" {
					critical = append(critical, fmt.Sprintf("❌ CRÍTICO: Header '%s' faltante - %s", headerName, check.Description))
				} else if check.Severity == "High" {
					issues = append(issues, fmt.Sprintf("❌ ALTO: Header '%s' faltante - %s", headerName, check.Description))
				} else {
					warnings = append(warnings, fmt.Sprintf("⚠️  MEDIO: Header '%s' faltante - %s", headerName, check.Description))
				}

				result.Evidence = append(result.Evidence, Evidence{
					Type:        "Missing Security Header",
					URL:         targetURL,
					Response:    fmt.Sprintf("Header %s no encontrado", headerName),
					Description: fmt.Sprintf("%s - %s", headerName, check.Description),
					Severity:    check.Severity,
				})
			} else {
				result.Details = append(result.Details, fmt.Sprintf("ℹ️  Header opcional '%s' no presente", headerName))
			}
		} else {
			// Header presente - verificar configuración
			isValid := t.validateHeaderValue(headerName, headerValue, check)
			if isValid.IsValid {
				result.Details = append(result.Details, fmt.Sprintf("✅ '%s': %s", headerName, headerValue))
			} else {
				if check.Severity == "Critical" {
					critical = append(critical, fmt.Sprintf("❌ CRÍTICO: '%s' mal configurado: %s - %s", headerName, headerValue, isValid.Issue))
				} else {
					issues = append(issues, fmt.Sprintf("❌ '%s' mal configurado: %s - %s", headerName, headerValue, isValid.Issue))
				}

				result.Evidence = append(result.Evidence, Evidence{
					Type:        "Misconfigured Security Header",
					URL:         targetURL,
					Response:    fmt.Sprintf("%s: %s", headerName, headerValue),
					Description: isValid.Issue,
					Severity:    check.Severity,
				})
			}
		}
	}

	// VERIFICAR HEADERS PELIGROSOS
	dangerousHeaders := map[string]string{
		"Server":              "Expone información del servidor",
		"X-Powered-By":        "Revela tecnología del backend",
		"X-AspNet-Version":    "Expone versión de ASP.NET",
		"X-AspNetMvc-Version": "Expone versión de ASP.NET MVC",
		"X-Generator":         "Revela CMS o framework usado",
		"X-Runtime":           "Expone tiempos de ejecución del servidor",
	}

	for headerName, description := range dangerousHeaders {
		headerValue := resp.Header.Get(headerName)
		if headerValue != "" {
			warnings = append(warnings, fmt.Sprintf("⚠️  Header '%s' expone información: %s", headerName, headerValue))
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "Information Disclosure",
				URL:         targetURL,
				Response:    fmt.Sprintf("%s: %s", headerName, headerValue),
				Description: description,
				Severity:    "Low",
			})
		}
	}

	// VERIFICAR COOKIES INSEGURAS
	cookieHeaders := resp.Header["Set-Cookie"]
	for _, cookie := range cookieHeaders {
		cookieIssues := t.analyzeCookie(cookie, isHTTPS)
		for _, issue := range cookieIssues {
			warnings = append(warnings, fmt.Sprintf("🍪 Cookie insegura: %s", issue))
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "Insecure Cookie",
				URL:         targetURL,
				Response:    cookie,
				Description: issue,
				Severity:    "Medium",
			})
		}
	}

	// VERIFICAR CORS MAL CONFIGURADO
	corsOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	if corsOrigin == "*" {
		corsCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
		if strings.EqualFold(corsCredentials, "true") {
			// Los navegadores ignoran las credenciales cuando el origen es '*',
			// así que es una configuración laxa, no una vulnerabilidad crítica.
			warnings = append(warnings, "⚠️  CORS usa '*' junto con credentials=true (revisar configuración)")
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "CORS Misconfiguration",
				URL:         targetURL,
				Response:    fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: %s", corsOrigin, corsCredentials),
				Description: "CORS laxo: wildcard con credenciales (los navegadores no envían credenciales con '*')",
				Severity:    "Low",
			})
		} else {
			warnings = append(warnings, "⚠️  CORS permite cualquier origen (sin credenciales)")
		}
	}

	// COMPILAR RESULTADO FINAL
	if len(critical) > 0 {
		result.Status = "Failed"
		result.Severity = "Critical"
		result.Description = fmt.Sprintf("CRÍTICO: %d problemas críticos de headers de seguridad", len(critical))
		result.Details = append(result.Details, critical...)
	} else if len(issues) > 0 {
		result.Status = "Failed"
		result.Severity = "High"
		result.Description = fmt.Sprintf("ALTO: %d problemas importantes de headers de seguridad", len(issues))
		result.Details = append(result.Details, issues...)
	} else if len(warnings) > 0 {
		result.Status = "Warning"
		result.Severity = "Medium"
		result.Description = fmt.Sprintf("MEDIO: %d problemas menores de headers de seguridad", len(warnings))
	}

	// Agregar warnings y detalles
	result.Details = append(result.Details, warnings...)

	return result
}

// HeaderCheck estructura para validación de headers
type HeaderCheck struct {
	Required      bool
	Severity      string
	Description   string
	ValidValues   []string
	InvalidValues []string
}

// HeaderValidation resultado de validación
type HeaderValidation struct {
	IsValid bool
	Issue   string
}

// validateHeaderValue valida el valor de un header específico
func (t *AdvancedSecurityHeadersTest) validateHeaderValue(headerName, headerValue string, check HeaderCheck) HeaderValidation {
	headerValueLower := strings.ToLower(headerValue)

	switch headerName {
	case "Content-Security-Policy":
		return t.validateCSP(headerValue)
	case "Strict-Transport-Security":
		return t.validateHSTS(headerValue)
	case "X-Frame-Options":
		return t.validateXFrameOptions(headerValue)
	case "X-Content-Type-Options":
		if headerValueLower != "nosniff" {
			return HeaderValidation{false, "Debe ser 'nosniff'"}
		}
	case "Referrer-Policy":
		validPolicies := []string{
			"no-referrer", "no-referrer-when-downgrade", "origin",
			"origin-when-cross-origin", "same-origin", "strict-origin",
			"strict-origin-when-cross-origin", "unsafe-url",
		}
		isValid := false
		for _, policy := range validPolicies {
			if headerValueLower == policy {
				isValid = true
				break
			}
		}
		if !isValid {
			return HeaderValidation{false, "Política no válida"}
		}
		if headerValueLower == "unsafe-url" || headerValueLower == "no-referrer-when-downgrade" {
			return HeaderValidation{false, fmt.Sprintf("Política insegura '%s'", headerValueLower)}
		}
	case "Permissions-Policy":
		if strings.Contains(headerValueLower, "*") {
			return HeaderValidation{false, "Permite cualquier origen para características del navegador"}
		}
		if strings.Contains(headerValueLower, "geolocation=(*)") || strings.Contains(headerValueLower, "camera=(*)") {
			return HeaderValidation{false, "Funcionalidades sensibles con wildcard (*)"}
		}
	case "Cross-Origin-Opener-Policy":
		if headerValueLower == "unsafe-none" {
			return HeaderValidation{false, "Contexto de navegación no aislado (unsafe-none)"}
		}
	}

	return HeaderValidation{true, ""}
}

// validateCSP valida Content-Security-Policy
func (t *AdvancedSecurityHeadersTest) validateCSP(csp string) HeaderValidation {
	cspLower := strings.ToLower(csp)

	// Verificar directivas inseguras
	if strings.Contains(cspLower, "'unsafe-inline'") {
		return HeaderValidation{false, "Contiene 'unsafe-inline' que es inseguro"}
	}
	if strings.Contains(cspLower, "'unsafe-eval'") {
		return HeaderValidation{false, "Contiene 'unsafe-eval' que es inseguro"}
	}
	if strings.Contains(cspLower, "default-src *") || strings.Contains(cspLower, "script-src *") {
		return HeaderValidation{false, "Permite cualquier fuente con '*' que es inseguro"}
	}

	// Verificar que tenga directivas básicas
	requiredDirectives := []string{"default-src", "script-src"}
	for _, directive := range requiredDirectives {
		if !strings.Contains(cspLower, directive) {
			return HeaderValidation{false, fmt.Sprintf("Falta directiva crítica '%s'", directive)}
		}
	}

	return HeaderValidation{true, ""}
}

// validateHSTS valida Strict-Transport-Security
func (t *AdvancedSecurityHeadersTest) validateHSTS(hsts string) HeaderValidation {
	hstsLower := strings.ToLower(hsts)

	if !strings.Contains(hstsLower, "max-age=") {
		return HeaderValidation{false, "Falta 'max-age'"}
	}

	if strings.Contains(hstsLower, "max-age=0") {
		return HeaderValidation{false, "max-age=0 deshabilita HSTS"}
	}

	// Verificar que max-age sea razonable (al menos 1 año)
	if strings.Contains(hstsLower, "max-age=") {
		// En una implementación completa, extraeríamos y validaríamos el número
		if !strings.Contains(hstsLower, "includesubdomains") {
			return HeaderValidation{false, "Recomendado incluir 'includeSubDomains'"}
		}
	}

	return HeaderValidation{true, ""}
}

// validateXFrameOptions valida X-Frame-Options
func (t *AdvancedSecurityHeadersTest) validateXFrameOptions(xfo string) HeaderValidation {
	xfoLower := strings.ToLower(xfo)

	validValues := []string{"deny", "sameorigin"}
	isValid := false
	for _, valid := range validValues {
		if xfoLower == valid {
			isValid = true
			break
		}
	}

	if !isValid {
		if strings.HasPrefix(xfoLower, "allow-from") {
			return HeaderValidation{false, "ALLOW-FROM está deprecado, usar CSP frame-ancestors"}
		}
		return HeaderValidation{false, "Valor no válido, usar DENY o SAMEORIGIN"}
	}

	return HeaderValidation{true, ""}
}

// analyzeCookie analiza una cookie en busca de problemas de seguridad.
// El flag Secure solo se exige cuando el sitio usa HTTPS: en HTTP el navegador
// no enviaría la cookie, por lo que reportarlo sería un falso positivo.
func (t *AdvancedSecurityHeadersTest) analyzeCookie(cookie string, isHTTPS bool) []string {
	var issues []string
	cookieLower := strings.ToLower(cookie)

	// Verificar flags de seguridad
	if isHTTPS && !strings.Contains(cookieLower, "secure") {
		issues = append(issues, "Cookie sin flag 'Secure'")
	}

	if !strings.Contains(cookieLower, "httponly") {
		issues = append(issues, "Cookie sin flag 'HttpOnly'")
	}

	if !strings.Contains(cookieLower, "samesite") {
		issues = append(issues, "Cookie sin atributo 'SameSite'")
	} else {
		// Verificar valor de SameSite
		if strings.Contains(cookieLower, "samesite=none") {
			issues = append(issues, "Cookie con 'SameSite=None' puede ser inseguro")
		}
	}

	// Verificar si es una cookie de sesión sin expiración
	if strings.Contains(cookieLower, "session") && !strings.Contains(cookieLower, "expires") && !strings.Contains(cookieLower, "max-age") {
		issues = append(issues, "Cookie de sesión sin tiempo de expiración")
	}

	return issues
}
