package tests

import (
	"fmt"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// OutdatedComponentsTest - Categoría A06:2021
type OutdatedComponentsTest struct{}

// Run ejecuta pruebas para detectar componentes vulnerables o desactualizados
func (t *OutdatedComponentsTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "A06:2021 - Vulnerable and Outdated Components",
		Status:      "Passed",
		Description: "Detección de componentes de software desactualizados o con versiones expuestas",
		Severity:    "Info",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		result.Status = "Failed"
		result.Description = fmt.Sprintf("Error conectando al objetivo: %v", err)
		return result
	}
	defer resp.Body.Close()

	// 1. Banner Grabbing - Analizar cabeceras de respuesta
	headersToAnalyze := map[string]string{
		"Server":           "Revela software del servidor web",
		"X-Powered-By":     "Revela lenguaje o framework",
		"X-AspNet-Version": "Revela versión de .NET",
		"X-Runtime":        "Revela entorno de ejecución",
	}

	for header, desc := range headersToAnalyze {
		val := resp.Header.Get(header)
		if val != "" {
			result.Details = append(result.Details, fmt.Sprintf("🔍 %s: %s (%s)", header, val, desc))

			// Si el banner es demasiado específico (contiene versiones)
			if containsVersion(val) {
				result.Evidence = append(result.Evidence, Evidence{
					Type:        "Information Disclosure (A06)",
					URL:         targetURL,
					Description: fmt.Sprintf("Versión de software expuesta en cabecera %s: %s", header, val),
					Severity:    "Low",
				})
				if result.Severity == "Info" {
					result.Severity = "Low"
				}
			}
		}
	}

	// 2. Fingerprinting - Buscar archivos o rutas que revelen componentes
	fingerprints := []struct {
		Path     string
		Pattern  string
		Software string
		Severity string
	}{
		{"/wp-includes/js/wp-embed.min.js", "wordpress", "WordPress", "Medium"},
		{"/pma/index.php", "phpMyAdmin", "phpMyAdmin (Admin Panel)", "High"},
		{"/drupal.js", "Drupal", "Drupal CMS", "Medium"},
		{"/server-status", "Apache Status", "Apache Server Status", "Medium"},
		{"/composer.json", "\"require\"", "Composer Configuration (Sensitive)", "High"},
		{"/package.json", "\"dependencies\"", "Node.js Dependencies (Sensitive)", "High"},
	}

	for _, fp := range fingerprints {
		fpURL := targetURL
		if !strings.HasSuffix(fpURL, "/") {
			fpURL += "/"
		}
		fpURL += strings.TrimPrefix(fp.Path, "/")

		fpResp, err := client.Get(fpURL)
		if err == nil {
			defer fpResp.Body.Close()
			if fpResp.StatusCode == 200 {
				result.Details = append(result.Details, fmt.Sprintf("⚠️ Componente detectado en: %s", fp.Path))
				result.Evidence = append(result.Evidence, Evidence{
					Type:        "Component Fingerprint",
					URL:         fpURL,
					Description: fmt.Sprintf("Se detectó %s en la ruta %s", fp.Software, fp.Path),
					Severity:    fp.Severity,
				})
				result.Status = "Warning"
				if fp.Severity == "High" {
					result.Severity = "High"
				} else if result.Severity != "High" {
					result.Severity = "Medium"
				}
			}
		}
	}

	if len(result.Evidence) > 0 {
		result.Description = "Se detectaron componentes con versiones expuestas o rutas sensibles"
	} else {
		result.Details = append(result.Details, "No se detectaron banners de versión específicos ni componentes vulnerables obvios.")
	}

	return result
}

// containsVersion verifica si un string parece contener un número de versión
func containsVersion(s string) bool {
	// Patrones comunes: 1.2.3, 2.4, v1, etc.
	hasDigit := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			hasDigit = true
			break
		}
	}

	if !hasDigit {
		return false
	}

	// Si contiene barras, puntos o espacios seguidos de números
	return strings.ContainsAny(s, "./ ")
}
