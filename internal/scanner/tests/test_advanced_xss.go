package tests

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	"github.com/versaSecurityTest/internal/config"
)

// AdvancedXSSTest - Test exhaustivo de Cross-Site Scripting
type AdvancedXSSTest struct {
	Discovery *DiscoveryResult
}

// Run ejecuta tests completos de XSS
func (t *AdvancedXSSTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "Advanced Cross-Site Scripting (XSS) Test",
		Status:      "Passed",
		Description: "No se detectaron vulnerabilidades XSS",
		Severity:    "None",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	// PAYLOADS EXHAUSTIVOS (reducidos para el ejemplo)
	xssPayloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"javascript:alert(1)",
		"'\"><script>alert(1)</script>",
		"\" onmouseover=alert(1) x=\"",
	}

	var endpointsToTest []string
	var paramsToTest []string

	if t.Discovery != nil && len(t.Discovery.Endpoints) > 0 {
		for _, info := range t.Discovery.Endpoints {
			for _, method := range info.Methods {
				if method == "GET" {
					endpointsToTest = append(endpointsToTest, info.Path)
					paramsToTest = append(paramsToTest, info.Params...)
				}
			}
		}
	} else {
		// Fallback si no hay descubrimiento
		endpointsToTest = []string{"/", "/search", "/contact", "/feedback"}
		paramsToTest = []string{"q", "name", "comment", "id"}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var vulnerabilitiesFound int

	// Limitar concurrencia interna
	semaphore := make(chan struct{}, 5)

	for _, endpoint := range endpointsToTest {
		for _, param := range paramsToTest {
			for _, payload := range xssPayloads {
				wg.Add(1)
				go func(e, p, pay string) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					testURL := fmt.Sprintf("%s%s?%s=%s", targetURL, e, p, url.QueryEscape(pay))

					resp, err := client.Get(testURL)
					if err != nil {
						return
					}
					defer resp.Body.Close()

					body, _ := io.ReadAll(resp.Body)

					xssVuln := t.analyzeXSSResponse(string(body), pay)
					if xssVuln.IsVulnerable {
						mu.Lock()
						vulnerabilitiesFound++
						result.Evidence = append(result.Evidence, Evidence{
							Type:        "Cross-Site Scripting",
							URL:         testURL,
							Payload:     pay,
							StatusCode:  resp.StatusCode,
							Response:    xssVuln.Evidence,
							Description: xssVuln.Description,
							Severity:    xssVuln.Severity,
						})
						mu.Unlock()
					}
				}(endpoint, param, payload)
			}
		}
	}

	wg.Wait()

	if vulnerabilitiesFound > 0 {
		result.Status = "Failed"
		result.Severity = "Critical"
		result.Description = fmt.Sprintf("CRÍTICO: Se detectaron %d vulnerabilidades XSS", vulnerabilitiesFound)
	}

	return result
}

// XSSVulnerability estructura para análisis de XSS
type XSSVulnerability struct {
	IsVulnerable bool
	Description  string
	Evidence     string
	Severity     string
}

// analyzeXSSResponse analiza la respuesta en busca de XSS
func (t *AdvancedXSSTest) analyzeXSSResponse(responseText, payload string) XSSVulnerability {
	responseLower := strings.ToLower(responseText)
	payloadLower := strings.ToLower(payload)

	// DETECCIÓN DE REFLECTED XSS

	// Buscar payload exacto sin codificar
	if strings.Contains(responseText, payload) {
		return XSSVulnerability{
			IsVulnerable: true,
			Description:  "Reflected XSS - payload reflejado sin sanitización",
			Evidence:     fmt.Sprintf("Payload '%s' encontrado sin codificar en la respuesta", payload),
			Severity:     "Critical",
		}
	}

	// Buscar elementos peligrosos del payload SOLO si están en el payload original
	dangerousElements := []string{
		"<script>", "</script>", "javascript:", "alert(", "onerror=",
		"onload=", "onfocus=", "onmouseover=", "onclick=", "eval=",
	}

	for _, element := range dangerousElements {
		elementLower := strings.ToLower(element)
		if strings.Contains(payloadLower, elementLower) && strings.Contains(responseLower, elementLower) {
			return XSSVulnerability{
				IsVulnerable: true,
				Description:  fmt.Sprintf("Reflected XSS - elemento peligroso '%s' reflejado", element),
				Evidence:     fmt.Sprintf("Elemento peligroso '%s' del payload encontrado en la respuesta", element),
				Severity:     "High",
			}
		}
	}

	// Buscar patrones de script tags - requerir al menos 2 que estén en el payload
	scriptPatterns := []string{
		"<script", "</script>", "<svg", "onload", "onerror", "javascript:",
	}

	reflectedElements := 0
	for _, pattern := range scriptPatterns {
		if strings.Contains(payloadLower, pattern) && strings.Contains(responseLower, pattern) {
			reflectedElements++
		}
	}

	if reflectedElements >= 2 {
		return XSSVulnerability{
			IsVulnerable: true,
			Description:  "Posible Reflected XSS - múltiples elementos del payload reflejados",
			Evidence:     fmt.Sprintf("%d elementos del payload encontrados en la respuesta", reflectedElements),
			Severity:     "Medium",
		}
	}

	// DETECCIÓN DE STORED XSS (análisis básico)
	// En un test real, esto requeriría hacer una segunda request para verificar persistencia
	if strings.Contains(payload, "<script>") && strings.Contains(responseText, "saved") ||
		strings.Contains(responseText, "stored") || strings.Contains(responseText, "posted") {
		return XSSVulnerability{
			IsVulnerable: true,
			Description:  "Posible Stored XSS - script almacenado en el servidor",
			Evidence:     fmt.Sprintf("Payload con script aparentemente almacenado: '%s'", payload),
			Severity:     "Critical",
		}
	}

	// DETECCIÓN DE DOM XSS (análisis básico)
	if strings.Contains(responseLower, "document.write") ||
		strings.Contains(responseLower, "innerhtml") ||
		strings.Contains(responseLower, "location.hash") ||
		strings.Contains(responseLower, "eval(") {

		// Si el payload también contiene código JavaScript
		if strings.Contains(payloadLower, "alert") || strings.Contains(payloadLower, "javascript:") {
			return XSSVulnerability{
				IsVulnerable: true,
				Description:  "Posible DOM XSS - código JavaScript en contexto DOM",
				Evidence:     fmt.Sprintf("Funciones DOM peligrosas detectadas con payload: '%s'", payload),
				Severity:     "High",
			}
		}
	}

	// Verificar si hay indicios de filtrado incompleto
	if strings.Contains(payload, "<script>") &&
		(strings.Contains(responseLower, "&lt;script&gt;") || strings.Contains(responseLower, "\\u003cscript\\u003e")) {
		return XSSVulnerability{
			IsVulnerable: false, // Bien filtrado
			Description:  "Payload XSS correctamente filtrado",
			Evidence:     "Script tag codificado correctamente",
			Severity:     "None",
		}
	}

	return XSSVulnerability{IsVulnerable: false}
}
