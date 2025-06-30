package tests

import (
	"fmt"
	"net/http"

	"github.com/versaSecurityTest/internal/config"
)

// AuthorizationTest - Categoría ATHZ (ATHZ-01 a ATHZ-04)
type AuthorizationTest struct{}

func (t *AuthorizationTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "ATHZ-01: Authorization Testing",
		Description: "Pruebas de autorización y control de acceso",
	}

	var details []string
	var evidence []Evidence

	// ATHZ-01: Verificar bypass de autorización con diferentes métodos HTTP
	protectedEndpoints := []string{
		"/admin", "/admin/", "/administrator", "/management",
		"/api/admin", "/api/users", "/api/config",
		"/dashboard", "/control-panel", "/settings",
	}

	httpMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}

	for _, endpoint := range protectedEndpoints {
		for _, method := range httpMethods {
			req, err := http.NewRequest(method, targetURL+endpoint, nil)
			if err != nil {
				continue
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			details = append(details, fmt.Sprintf("Probando %s %s (Status: %d)", method, endpoint, resp.StatusCode))

			// Si no es 401 o 403, podría ser un bypass
			if resp.StatusCode != 401 && resp.StatusCode != 403 && resp.StatusCode != 405 && resp.StatusCode != 404 {
				if resp.StatusCode == 200 {
					evidence = append(evidence, Evidence{
						Type:        "Authorization Bypass",
						URL:         targetURL + endpoint,
						StatusCode:  resp.StatusCode,
						Description: fmt.Sprintf("Posible bypass de autorización con método %s en %s", method, endpoint),
						Severity:    "High",
					})
				}
			}
		}
	}

	// ATHZ-02: Verificar escalación de privilegios horizontal
	userEndpoints := []string{
		"/user/1", "/user/2", "/profile/1", "/profile/2",
		"/api/user/1", "/api/user/2", "/account/1", "/account/2",
	}

	for _, endpoint := range userEndpoints {
		resp, err := client.Get(targetURL + endpoint)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		details = append(details, fmt.Sprintf("Verificando acceso a %s (Status: %d)", endpoint, resp.StatusCode))

		if resp.StatusCode == 200 {
			evidence = append(evidence, Evidence{
				Type:        "Horizontal Privilege Escalation",
				URL:         targetURL + endpoint,
				StatusCode:  resp.StatusCode,
				Description: fmt.Sprintf("Posible acceso no autorizado a datos de usuario: %s", endpoint),
				Severity:    "High",
			})
		}
	}

	// ATHZ-03: Verificar controles de acceso en APIs
	apiEndpoints := []string{
		"/api/v1/admin", "/api/v2/admin", "/api/admin",
		"/api/v1/users", "/api/v2/users", "/api/users",
		"/api/v1/config", "/api/v2/config", "/api/config",
		"/api/internal", "/api/private", "/api/secure",
	}

	for _, endpoint := range apiEndpoints {
		resp, err := client.Get(targetURL + endpoint)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		details = append(details, fmt.Sprintf("Verificando API %s (Status: %d)", endpoint, resp.StatusCode))

		// APIs que devuelven 200 sin autenticación pueden ser problemáticas
		if resp.StatusCode == 200 {
			evidence = append(evidence, Evidence{
				Type:        "API Access Control",
				URL:         targetURL + endpoint,
				StatusCode:  resp.StatusCode,
				Description: fmt.Sprintf("API accesible sin autenticación: %s", endpoint),
				Severity:    "Medium",
			})
		}
	}

	result.Details = details
	result.Evidence = evidence

	if len(evidence) == 0 {
		result.Status = "Passed"
		result.Severity = "Info"
	} else {
		result.Status = "Failed"
		// Determinar severidad máxima
		maxSeverity := "Low"
		for _, ev := range evidence {
			if ev.Severity == "High" {
				maxSeverity = "High"
				break
			} else if ev.Severity == "Medium" && maxSeverity != "High" {
				maxSeverity = "Medium"
			}
		}
		result.Severity = maxSeverity
	}

	return result
}

// DirectObjectReferenceTest - ATHZ-04: Direct Object Reference
type DirectObjectReferenceTest struct{}

func (t *DirectObjectReferenceTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "ATHZ-04: Direct Object Reference Testing",
		Description: "Pruebas de referencias directas a objetos inseguros",
	}

	var details []string
	var evidence []Evidence

	// Probar diferentes tipos de identificadores
	objectEndpoints := []struct {
		pattern string
		ids     []string
		desc    string
	}{
		{"/user/%s", []string{"1", "2", "100", "999", "admin", "test"}, "usuarios"},
		{"/document/%s", []string{"1", "2", "100", "999"}, "documentos"},
		{"/file/%s", []string{"1", "2", "config", "backup"}, "archivos"},
		{"/api/user/%s", []string{"1", "2", "100", "admin"}, "API usuarios"},
		{"/api/order/%s", []string{"1", "2", "100", "999"}, "API órdenes"},
	}

	for _, endpoint := range objectEndpoints {
		for _, id := range endpoint.ids {
			testURL := targetURL + fmt.Sprintf(endpoint.pattern, id)
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			details = append(details, fmt.Sprintf("Probando %s con ID %s (Status: %d)", endpoint.desc, id, resp.StatusCode))

			// Si devuelve 200, podría ser una referencia directa insegura
			if resp.StatusCode == 200 {
				evidence = append(evidence, Evidence{
					Type:        "Insecure Direct Object Reference",
					URL:         testURL,
					StatusCode:  resp.StatusCode,
					Description: fmt.Sprintf("Posible acceso directo no autorizado a %s con ID %s", endpoint.desc, id),
					Severity:    "High",
				})
			}
		}
	}

	// Probar manipulación de parámetros en URLs
	parameterTests := []string{
		"?id=1", "?id=2", "?id=../", "?id=admin",
		"?user=1", "?user=2", "?user=admin",
		"?file=config", "?file=../config", "?file=backup",
	}

	for _, param := range parameterTests {
		testURL := targetURL + "/" + param
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		details = append(details, fmt.Sprintf("Probando parámetro %s (Status: %d)", param, resp.StatusCode))

		if resp.StatusCode == 200 {
			evidence = append(evidence, Evidence{
				Type:        "Parameter Manipulation",
				URL:         testURL,
				StatusCode:  resp.StatusCode,
				Description: fmt.Sprintf("Posible manipulación de parámetros: %s", param),
				Severity:    "Medium",
			})
		}
	}

	result.Details = details
	result.Evidence = evidence

	if len(evidence) == 0 {
		result.Status = "Passed"
		result.Severity = "Info"
	} else {
		result.Status = "Failed"
		// Determinar severidad máxima
		maxSeverity := "Low"
		for _, ev := range evidence {
			if ev.Severity == "High" {
				maxSeverity = "High"
				break
			} else if ev.Severity == "Medium" && maxSeverity != "High" {
				maxSeverity = "Medium"
			}
		}
		result.Severity = maxSeverity
	}

	return result
}
