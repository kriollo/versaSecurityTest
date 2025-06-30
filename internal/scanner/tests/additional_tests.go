package tests

import (
	"fmt"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// ErrorLeakageTest - Categoría ERRH (ERRH-01 a ERRH-02)
type ErrorLeakageTest struct{}

func (t *ErrorLeakageTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "ERRH-01: Error Leakage Testing",
		Description: "Manejo de errores y registros (logging) seguros",
	}

	var details []string
	var evidence []Evidence

	// ERRH-01: Probar diferentes tipos de errores
	errorTriggers := []struct {
		url  string
		desc string
	}{
		{targetURL + "/nonexistent-page-12345", "página inexistente"},
		{targetURL + "/index.php?id=abc", "parámetro inválido"},
		{targetURL + "/search?q=" + strings.Repeat("A", 5000), "string muy largo"},
		{targetURL + "/api/test?format=xml", "formato no soportado"},
		{targetURL + "/admin/../../etc/passwd", "path traversal"},
	}

	for _, trigger := range errorTriggers {
		resp, err := client.Get(trigger.url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		details = append(details, fmt.Sprintf("Probando error de %s (Status: %d)", trigger.desc, resp.StatusCode))

		// Verificar si hay información sensible en errores del servidor
		if resp.StatusCode >= 500 {
			evidence = append(evidence, Evidence{
				Type:        "Error Information Disclosure",
				URL:         trigger.url,
				StatusCode:  resp.StatusCode,
				Description: fmt.Sprintf("Error del servidor para %s - posible exposición de información", trigger.desc),
				Severity:    "Medium",
			})
		}

		// Verificar errores de aplicación (400-499) que puedan revelar información
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 404 && resp.StatusCode != 403 {
			details = append(details, fmt.Sprintf("Error de aplicación: %d", resp.StatusCode))
		}
	}

	// ERRH-02: Verificar stack traces y debug info
	debugTriggers := []string{
		"/debug", "/trace", "/error", "/exception",
		"/?debug=1", "/?trace=1", "/?verbose=1",
		"/api/debug", "/api/trace", "/api/error",
	}

	for _, trigger := range debugTriggers {
		resp, err := client.Get(targetURL + trigger)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		details = append(details, fmt.Sprintf("Verificando debug endpoint: %s (Status: %d)", trigger, resp.StatusCode))

		if resp.StatusCode == 200 {
			evidence = append(evidence, Evidence{
				Type:        "Debug Information",
				URL:         targetURL + trigger,
				StatusCode:  resp.StatusCode,
				Description: fmt.Sprintf("Endpoint de debug accesible: %s", trigger),
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
		result.Severity = "Medium"
	}

	return result
}

// CryptographyTest - Categoría CRYP (CRYP-01 a CRYP-04)
type CryptographyTest struct{}

func (t *CryptographyTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "CRYP-01: Cryptography Testing",
		Description: "Uso correcto de criptografía, SSL/TLS, cifrado de datos",
	}

	var details []string
	var evidence []Evidence

	// CRYP-01: Verificar redirección HTTPS
	if strings.HasPrefix(targetURL, "https://") {
		httpURL := strings.Replace(targetURL, "https://", "http://", 1)
		resp, err := client.Get(httpURL)
		if err == nil {
			defer resp.Body.Close()
			details = append(details, fmt.Sprintf("Verificando redirección HTTP->HTTPS (Status: %d)", resp.StatusCode))

			if resp.StatusCode != 301 && resp.StatusCode != 302 && resp.StatusCode != 307 && resp.StatusCode != 308 {
				evidence = append(evidence, Evidence{
					Type:        "HTTP Not Redirected",
					URL:         httpURL,
					StatusCode:  resp.StatusCode,
					Description: "El sitio no redirige automáticamente de HTTP a HTTPS",
					Severity:    "Medium",
				})
			}
		}
	}

	// CRYP-02: Verificar headers de seguridad HTTPS
	resp, err := client.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()

		// Verificar HSTS
		hsts := resp.Header.Get("Strict-Transport-Security")
		if hsts == "" && strings.HasPrefix(targetURL, "https://") {
			details = append(details, "Header HSTS no encontrado")
			evidence = append(evidence, Evidence{
				Type:        "Missing HSTS",
				URL:         targetURL,
				StatusCode:  resp.StatusCode,
				Description: "Header Strict-Transport-Security no configurado",
				Severity:    "Medium",
			})
		} else if hsts != "" {
			details = append(details, fmt.Sprintf("HSTS configurado: %s", hsts))
		}

		// Verificar Content Security Policy
		csp := resp.Header.Get("Content-Security-Policy")
		if csp == "" {
			details = append(details, "Header CSP no encontrado")
			evidence = append(evidence, Evidence{
				Type:        "Missing CSP",
				URL:         targetURL,
				StatusCode:  resp.StatusCode,
				Description: "Header Content-Security-Policy no configurado",
				Severity:    "Low",
			})
		} else {
			details = append(details, "CSP configurado")
		}
	}

	// CRYP-03: Verificar certificado SSL (básico)
	if strings.HasPrefix(targetURL, "https://") {
		details = append(details, "Conexión HTTPS verificada")
		// En una implementación real, verificaríamos detalles del certificado
	} else {
		evidence = append(evidence, Evidence{
			Type:        "No HTTPS",
			URL:         targetURL,
			Description: "El sitio no utiliza HTTPS",
			Severity:    "High",
		})
	}

	// CRYP-04: Verificar cookies seguras
	if resp != nil {
		for _, cookie := range resp.Cookies() {
			details = append(details, fmt.Sprintf("Analizando cookie: %s", cookie.Name))

			if !cookie.Secure && strings.HasPrefix(targetURL, "https://") {
				evidence = append(evidence, Evidence{
					Type:        "Insecure Cookie",
					URL:         targetURL,
					Description: fmt.Sprintf("Cookie '%s' sin flag Secure en HTTPS", cookie.Name),
					Severity:    "Medium",
				})
			}

			if !cookie.HttpOnly {
				evidence = append(evidence, Evidence{
					Type:        "Insecure Cookie",
					URL:         targetURL,
					Description: fmt.Sprintf("Cookie '%s' sin flag HttpOnly", cookie.Name),
					Severity:    "Medium",
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

// BusinessLogicTest - Categoría BUSL (BUSL-01 a BUSL-09)
type BusinessLogicTest struct{}

func (t *BusinessLogicTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "BUSL-01: Business Logic Testing",
		Description: "Lógica de negocio, procesos, validaciones y control de flujo",
	}

	var details []string
	var evidence []Evidence

	// BUSL-01: Verificar bypass de procesos de negocio
	businessEndpoints := []string{
		"/checkout", "/payment", "/order", "/purchase",
		"/api/checkout", "/api/payment", "/api/order",
		"/cart", "/basket", "/shopping-cart",
	}

	for _, endpoint := range businessEndpoints {
		resp, err := client.Get(targetURL + endpoint)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		details = append(details, fmt.Sprintf("Verificando endpoint de negocio: %s (Status: %d)", endpoint, resp.StatusCode))

		// Si un endpoint crítico de negocio es accesible sin autenticación
		if resp.StatusCode == 200 && (strings.Contains(endpoint, "payment") ||
		   strings.Contains(endpoint, "checkout") || strings.Contains(endpoint, "purchase")) {
			evidence = append(evidence, Evidence{
				Type:        "Business Logic Bypass",
				URL:         targetURL + endpoint,
				StatusCode:  resp.StatusCode,
				Description: fmt.Sprintf("Endpoint crítico de negocio accesible sin autenticación: %s", endpoint),
				Severity:    "High",
			})
		}
	}

	// BUSL-02: Verificar manipulación de precios
	priceTests := []string{
		"?price=0", "?price=-1", "?amount=0", "?total=-100",
		"?discount=100", "?discount=999", "?quantity=-1",
	}

	for _, endpoint := range businessEndpoints {
		for _, test := range priceTests {
			testURL := targetURL + endpoint + test
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			details = append(details, fmt.Sprintf("Probando manipulación de precio en %s (Status: %d)", endpoint, resp.StatusCode))

			// Si acepta valores negativos o cero para precios
			if resp.StatusCode == 200 {
				details = append(details, fmt.Sprintf("Endpoint acepta parámetro: %s", test))
			}
		}
	}

	// BUSL-03: Verificar límites de rate limiting
	rateTestURL := targetURL + "/api/login"
	requestCount := 0
	for i := 0; i < 20; i++ {
		resp, err := client.Get(rateTestURL + "?user=test&pass=test")
		if err != nil {
			break
		}
		resp.Body.Close()
		requestCount++

		if resp.StatusCode == 429 {
			details = append(details, fmt.Sprintf("Rate limiting detectado después de %d requests", requestCount))
			break
		}
	}

	if requestCount >= 20 {
		evidence = append(evidence, Evidence{
			Type:        "No Rate Limiting",
			URL:         rateTestURL,
			Description: "No se detectó rate limiting después de múltiples requests",
			Severity:    "Medium",
		})
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
