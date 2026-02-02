package tests

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// ClientSideTest - Categoría CLNT (CLNT-01 a CLNT-13)
type ClientSideTest struct{}

func (t *ClientSideTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "CLNT-01: Client-Side Testing",
		Description: "Pruebas del lado del cliente, XSS, clickjacking, validaciones JS",
	}

	var details []string
	var evidence []Evidence

	// CLNT-01: Verificar headers anti-clickjacking
	resp, err := client.Get(targetURL)
	if err != nil {
		result.Status = "Failed"
		result.Description = fmt.Sprintf("Error conectando: %v", err)
		return result
	}
	// Si recibimos 429, no podemos verificar headers confiablemente
	if resp.StatusCode == 429 {
		details = append(details, "Rate limit detectado (429) - omitiendo verificación de headers de seguridad")
		result.Status = "Passed"
		result.Severity = "Info"
		return result
	}
	defer resp.Body.Close()

	// Verificar X-Frame-Options
	xFrameOptions := resp.Header.Get("X-Frame-Options")
	if xFrameOptions == "" {
		details = append(details, "Header X-Frame-Options no encontrado")
		evidence = append(evidence, Evidence{
			Type:        "Missing Anti-Clickjacking",
			URL:         targetURL,
			StatusCode:  resp.StatusCode,
			Description: "Header X-Frame-Options no configurado - vulnerable a clickjacking",
			Severity:    "Medium",
		})
	} else {
		details = append(details, fmt.Sprintf("X-Frame-Options configurado: %s", xFrameOptions))
	}

	// CLNT-02: Verificar Content Security Policy
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		details = append(details, "Content Security Policy no configurado")
		evidence = append(evidence, Evidence{
			Type:        "Missing CSP",
			URL:         targetURL,
			StatusCode:  resp.StatusCode,
			Description: "Content Security Policy no configurado - vulnerable a XSS",
			Severity:    "Medium",
		})
	} else {
		details = append(details, "CSP configurado")

		// Verificar directivas peligrosas en CSP
		if strings.Contains(csp, "unsafe-inline") {
			evidence = append(evidence, Evidence{
				Type:        "Weak CSP",
				URL:         targetURL,
				StatusCode:  resp.StatusCode,
				Description: "CSP permite 'unsafe-inline' - debilita protección XSS",
				Severity:    "Low",
			})
		}

		if strings.Contains(csp, "unsafe-eval") {
			evidence = append(evidence, Evidence{
				Type:        "Weak CSP",
				URL:         targetURL,
				StatusCode:  resp.StatusCode,
				Description: "CSP permite 'unsafe-eval' - debilita protección XSS",
				Severity:    "Low",
			})
		}
	}

	// CLNT-03: Verificar MIME type sniffing protection
	xContentType := resp.Header.Get("X-Content-Type-Options")
	if xContentType != "nosniff" {
		details = append(details, "Header X-Content-Type-Options no configurado")
		evidence = append(evidence, Evidence{
			Type:        "MIME Sniffing",
			URL:         targetURL,
			StatusCode:  resp.StatusCode,
			Description: "X-Content-Type-Options no configurado - vulnerable a MIME sniffing",
			Severity:    "Low",
		})
	}

	// CLNT-04: Verificar XSS Protection
	xssProtection := resp.Header.Get("X-XSS-Protection")
	if xssProtection == "" {
		details = append(details, "Header X-XSS-Protection no encontrado")
		evidence = append(evidence, Evidence{
			Type:        "Missing XSS Protection",
			URL:         targetURL,
			StatusCode:  resp.StatusCode,
			Description: "X-XSS-Protection no configurado",
			Severity:    "Low",
		})
	}

	// CLNT-05: Probar inyección DOM-based XSS
	domXSSEndpoints := []string{
		"/#<script>alert(1)</script>",
		"/?redirect=javascript:alert(1)",
		"/#javascript:alert(1)",
		"/?callback=alert",
	}

	for _, endpoint := range domXSSEndpoints {
		testURL := targetURL + endpoint
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		details = append(details, fmt.Sprintf("Probando DOM XSS: %s (Status: %d)", endpoint, resp.StatusCode))

		if resp.StatusCode == 200 {
			details = append(details, fmt.Sprintf("Endpoint DOM XSS accesible: %s", endpoint))
		}
	}

	// CLNT-06: Verificar endpoints JSONP
	jsonpTests := []string{
		"?callback=test", "?jsonp=test", "?cb=test",
		"?jsoncallback=test", "?callback=alert",
	}

	apiEndpoints := []string{"/api/", "/json/", "/jsonp/", "/data/"}

	for _, apiEndpoint := range apiEndpoints {
		for _, jsonpTest := range jsonpTests {
			testURL := targetURL + apiEndpoint + jsonpTest
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			details = append(details, fmt.Sprintf("Probando JSONP: %s (Status: %d)", apiEndpoint+jsonpTest, resp.StatusCode))

			if resp.StatusCode == 200 {
				evidence = append(evidence, Evidence{
					Type:        "JSONP Vulnerability",
					URL:         testURL,
					StatusCode:  resp.StatusCode,
					Description: fmt.Sprintf("Endpoint JSONP vulnerable: %s", apiEndpoint),
					Severity:    "Medium",
				})
			} else if resp.StatusCode == 429 {
				details = append(details, fmt.Sprintf("Rate limit en JSONP: %s", apiEndpoint))
			}
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
			if ev.Severity == "Medium" && maxSeverity != "High" {
				maxSeverity = "Medium"
			}
		}
		result.Severity = maxSeverity
	}

	return result
}

// APISecurityTest - Categoría APIT (APIT-01 a APIT-xx)
type APISecurityTest struct{}

func (t *APISecurityTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "APIT-01: API Security Testing",
		Description: "Seguridad en APIs REST, GraphQL y SOAP",
	}

	var details []string
	var evidence []Evidence

	// APIT-01: Detectar endpoints de API
	apiPaths := []string{
		"/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
		"/rest", "/rest/", "/graphql", "/soap",
		"/json", "/xml", "/rpc", "/endpoints",
	}

	for _, path := range apiPaths {
		resp, err := client.Get(targetURL + path)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		details = append(details, fmt.Sprintf("Verificando API endpoint: %s (Status: %d)", path, resp.StatusCode))

		if resp.StatusCode == 200 {
			details = append(details, fmt.Sprintf("API endpoint encontrado: %s", path))

			// Verificar si hay documentación expuesta
			if strings.Contains(path, "api") {
				// Intentar encontrar documentación Swagger/OpenAPI
				swaggerPaths := []string{"/swagger", "/swagger-ui", "/docs", "/api-docs", "/openapi.json"}
				for _, swaggerPath := range swaggerPaths {
					swaggerResp, err := client.Get(targetURL + swaggerPath)
					if err != nil {
						continue
					}
					defer swaggerResp.Body.Close()

					if swaggerResp.StatusCode == 200 {
						evidence = append(evidence, Evidence{
							Type:        "API Documentation Exposed",
							URL:         targetURL + swaggerPath,
							StatusCode:  swaggerResp.StatusCode,
							Description: fmt.Sprintf("Documentación de API expuesta: %s", swaggerPath),
							Severity:    "Low",
						})
					}
				}
			}
		}
	}

	// APIT-02: Verificar métodos HTTP en APIs
	apiTestPaths := []string{"/api/users", "/api/user", "/api/data", "/api/config"}
	httpMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}

	for _, apiPath := range apiTestPaths {
		for _, method := range httpMethods {
			// Verificar si el endpoint responde sin autenticación
			if method == "GET" {
				resp, err := client.Get(targetURL + apiPath)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				details = append(details, fmt.Sprintf("Probando %s %s (Status: %d)", method, apiPath, resp.StatusCode))

				if resp.StatusCode == 200 {
					evidence = append(evidence, Evidence{
						Type:        "Unauthorized API Access",
						URL:         targetURL + apiPath,
						StatusCode:  resp.StatusCode,
						Description: fmt.Sprintf("API endpoint accesible sin autenticación: %s", apiPath),
						Severity:    "High",
					})
				}
			}
		}
	}

	// APIT-03: Verificar rate limiting en APIs
	rateTestAPI := targetURL + "/api/test"
	requestCount := 0
	for i := 0; i < 30; i++ {
		resp, err := client.Get(rateTestAPI)
		if err != nil {
			break
		}
		resp.Body.Close()
		requestCount++

		if resp.StatusCode == 429 {
			details = append(details, fmt.Sprintf("Rate limiting en API detectado después de %d requests", requestCount))
			break
		}
	}

	if requestCount >= 30 {
		evidence = append(evidence, Evidence{
			Type:        "No API Rate Limiting",
			URL:         rateTestAPI,
			Description: "No se detectó rate limiting en API después de múltiples requests",
			Severity:    "Medium",
		})
	}

	// APIT-04: Verificar CORS policy
	corsTestURL := targetURL + "/api/test"
	resp, err := client.Get(corsTestURL)
	if err == nil {
		defer resp.Body.Close()

		accessControlOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		if accessControlOrigin == "*" {
			evidence = append(evidence, Evidence{
				Type:        "Permissive CORS",
				URL:         corsTestURL,
				StatusCode:  resp.StatusCode,
				Description: "CORS policy demasiado permisiva (Access-Control-Allow-Origin: *)",
				Severity:    "Medium",
			})
		}

		details = append(details, fmt.Sprintf("CORS Origin: %s", accessControlOrigin))
	}

	// APIT-05: Probar inyección en parámetros de API
	injectionPayloads := []string{
		"'", "\"", "<script>", "{{7*7}}", "${7*7}",
		"../", "%2e%2e%2f", "../../etc/passwd",
	}

	for _, apiPath := range apiTestPaths {
		for _, payload := range injectionPayloads {
			testURL := targetURL + apiPath + "?param=" + url.QueryEscape(payload)
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			details = append(details, fmt.Sprintf("Probando inyección en API %s (Status: %d)", apiPath, resp.StatusCode))

			if resp.StatusCode == 500 {
				evidence = append(evidence, Evidence{
					Type:        "API Injection Vulnerability",
					URL:         testURL,
					Payload:     payload,
					StatusCode:  resp.StatusCode,
					Description: fmt.Sprintf("Posible vulnerabilidad de inyección en API: %s", apiPath),
					Severity:    "High",
				})
			}
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
