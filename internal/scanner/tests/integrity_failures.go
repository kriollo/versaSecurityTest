package tests

import (
	"fmt"
	"io"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// DataIntegrityTest - Categoría A08:2021
type DataIntegrityTest struct{}

// Run ejecuta pruebas para detectar fallos en la integridad de datos y software
func (t *DataIntegrityTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "A08:2021 - Software and Data Integrity Failures",
		Status:      "Passed",
		Description: "Detección de formatos de serialización inseguros y falta de integridad",
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

	// 1. Analizar Cookies en busca de serialización insegura
	for _, cookie := range resp.Cookies() {
		val := cookie.Value

		// Detección de serialización PHP
		if strings.Contains(val, "O:") && strings.Contains(val, ":\"") && strings.Contains(val, "\":") {
			result.Details = append(result.Details, fmt.Sprintf("⚠️ Posible serialización PHP en cookie: %s", cookie.Name))
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "Insecure Deserialization (PHP)",
				URL:         targetURL,
				Description: fmt.Sprintf("La cookie '%s' parece contener un objeto serializado de PHP", cookie.Name),
				Severity:    "High",
			})
			result.Status = "Warning"
			result.Severity = "High"
		}

		// Detección de base64 que podría ocultar objetos
		if isLikelyBase64(val) && len(val) > 20 {
			// Intentar decodificar y buscar patrones (placeholder para lógica más avanzada)
			result.Details = append(result.Details, fmt.Sprintf("🔍 Cookie '%s' tiene formato Base64", cookie.Name))
		}
	}

	// 2. Buscar enlaces a actualizaciones sin integridad (firmas)
	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	updatePatterns := []string{"update", "download", "install", "installer"}
	for _, pattern := range updatePatterns {
		if strings.Contains(strings.ToLower(content), pattern) {
			// Si hay enlaces a descargas de software, verificar si mencionan firmas o hashes
			if !strings.Contains(strings.ToLower(content), "sha256") &&
				!strings.Contains(strings.ToLower(content), "sig") &&
				!strings.Contains(strings.ToLower(content), "gpg") {
				result.Details = append(result.Details, fmt.Sprintf("🔍 Se detectó mención a '%s' sin referencia evidente a verificación de integridad", pattern))
			}
		}
	}

	if len(result.Evidence) > 0 {
		result.Description = "Se detectaron posibles fallos de integridad en datos serializados"
	}

	return result
}

// isLikelyBase64 una verificación básica de caracteres base64
func isLikelyBase64(s string) bool {
	if len(s)%4 != 0 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	return true
}
