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

	// Firmas de fuga REAL: rastros de error/stack trace de frameworks, no la mera aparición de palabras
	// como "error" o "admin" (eso aparece en cualquier página y daba falsos positivos constantes).
	patterns := map[string]string{
		"fatal error:":                      "Error fatal de PHP expuesto",
		"<b>warning</b>:":                   "Warning de PHP expuesto",
		"<b>notice</b>:":                    "Notice de PHP expuesto",
		"uncaught exception":                "Excepción sin capturar expuesta",
		"traceback (most recent call last)": "Traceback de Python expuesto",
		"exception in thread":               "Stack trace de Java expuesto",
		"sqlstate[":                         "Error de base de datos (SQLSTATE) expuesto",
		"undefined index":                   "Aviso de PHP (undefined index) expuesto",
		".php on line":                      "Ruta y línea de PHP expuesta",
		"#0 /":                              "Stack trace con rutas del servidor expuesto",
		"goroutine 1 [":                     "Stack trace de Go expuesto",
		"at object.<anonymous>":             "Stack trace de Node.js expuesto",
		"/node_modules/":                    "Ruta de Node.js (node_modules) expuesta en error",
		"at java.":                          "Stack trace de Java expuesto",
		"javax.servlet":                     "Stack trace de Java/Servlet expuesto",
		"actioncontroller::":                "Stack trace de Ruby on Rails expuesto",
		"system.web.":                       "Stack trace de ASP.NET expuesto",
		"/var/www/":                         "Ruta del servidor expuesta en la respuesta",
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
