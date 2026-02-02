package tests

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/versaSecurityTest/internal/config"
)

// InfoGatheringTest implementa tests de recolección de información
type InfoGatheringTest struct{}

// Run ejecuta todos los tests de recolección de información
func (t *InfoGatheringTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "Information Gathering",
		Status:      "Passed",
		Description: "Recolección de información del servidor y aplicación web",
		Severity:    "Info",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	// INFO-01: Enumeración de cabeceras HTTP
	t.testHTTPHeaders(targetURL, client, &result)

	// INFO-02: Detección de tecnologías
	t.testTechnologyDetection(targetURL, client, &result)

	// INFO-03: Recolección de metadatos HTML/JS
	t.testMetadataCollection(targetURL, client, &result)

	// INFO-04: Búsqueda de comentarios expuestos
	t.testExposedComments(targetURL, client, &result)

	// INFO-05: Detección de rutas comunes
	t.testCommonPaths(targetURL, client, &result)

	// Determinar el estado final
	if len(result.Details) == 0 {
		result.Description = "No se encontró información sensible expuesta"
	} else {
		result.Status = "Warning"
		result.Description = fmt.Sprintf("Se recopiló información del servidor (%d elementos)", len(result.Details))
		result.Severity = "Low"
	}

	return result
}

// INFO-01: Enumeración de cabeceras HTTP
func (t *InfoGatheringTest) testHTTPHeaders(targetURL string, client HTTPClient, result *TestResult) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Headers informativos que pueden revelar tecnologías
	informativeHeaders := map[string]string{
		"Server":                  "Servidor web",
		"X-Powered-By":            "Tecnología backend",
		"X-AspNet-Version":        "Versión ASP.NET",
		"X-Generator":             "Generador de contenido",
		"X-Drupal-Cache":          "CMS Drupal",
		"X-Pingback":              "WordPress pingback",
		"X-Frame-Options":         "Protección clickjacking",
		"Content-Security-Policy": "Política de seguridad",
	}

	for header, description := range informativeHeaders {
		if value := resp.Header.Get(header); value != "" {
			result.Details = append(result.Details, fmt.Sprintf("Header '%s': %s (%s)", header, value, description))
			result.Evidence = append(result.Evidence, Evidence{
				Type:     "HTTP Header Information",
				URL:      targetURL,
				Response: fmt.Sprintf("%s: %s", header, value),
			})
		}
	}
}

// INFO-02: Detección de tecnologías
func (t *InfoGatheringTest) testTechnologyDetection(targetURL string, client HTTPClient, result *TestResult) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := ReadResponseBody(resp)
	if err != nil {
		return
	}

	// Patrones para detectar tecnologías
	techPatterns := map[string]*regexp.Regexp{
		"WordPress": regexp.MustCompile(`wp-content|wp-includes|/wp-admin/`),
		"Drupal":    regexp.MustCompile(`Drupal\.settings|drupal\.js`),
		"Joomla":    regexp.MustCompile(`/components/com_|Joomla!`),
		"PHP":       regexp.MustCompile(`\.php[\"'?]|X-Powered-By.*PHP`),
		"ASP.NET":   regexp.MustCompile(`__VIEWSTATE|asp\.net|\.aspx`),
		"Node.js":   regexp.MustCompile(`X-Powered-By.*Express`),
		"Angular":   regexp.MustCompile(`ng-app|angular\.js`),
		"React":     regexp.MustCompile(`react|_reactInternalInstance`),
		"Vue.js":    regexp.MustCompile(`vue\.js|v-if|v-for`),
		"jQuery":    regexp.MustCompile(`jquery|\\$\\(document\\)`),
		"Bootstrap": regexp.MustCompile(`bootstrap\.css|bootstrap\.js`),
	}

	for tech, pattern := range techPatterns {
		if pattern.MatchString(body) {
			result.Details = append(result.Details, fmt.Sprintf("Tecnología detectada: %s", tech))
			result.Evidence = append(result.Evidence, Evidence{
				Type:     "Technology Detection",
				URL:      targetURL,
				Response: fmt.Sprintf("Detected %s technology", tech),
			})
		}
	}
}

// INFO-03: Recolección de metadatos HTML/JS
func (t *InfoGatheringTest) testMetadataCollection(targetURL string, client HTTPClient, result *TestResult) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := ReadResponseBody(resp)
	if err != nil {
		return
	}

	// Buscar metadatos importantes
	metaPatterns := map[string]*regexp.Regexp{
		"Generator":   regexp.MustCompile(`<meta name=["\']generator["\'] content=["\']([^"']+)["\']`),
		"Description": regexp.MustCompile(`<meta name=["\']description["\'] content=["\']([^"']+)["\']`),
		"Keywords":    regexp.MustCompile(`<meta name=["\']keywords["\'] content=["\']([^"']+)["\']`),
		"Author":      regexp.MustCompile(`<meta name=["\']author["\'] content=["\']([^"']+)["\']`),
		"Copyright":   regexp.MustCompile(`<meta name=["\']copyright["\'] content=["\']([^"']+)["\']`),
		"Robots":      regexp.MustCompile(`<meta name=["\']robots["\'] content=["\']([^"']+)["\']`),
	}

	for metaType, pattern := range metaPatterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 1 {
				result.Details = append(result.Details, fmt.Sprintf("Meta %s: %s", metaType, match[1]))
				result.Evidence = append(result.Evidence, Evidence{
					Type:     "HTML Metadata",
					URL:      targetURL,
					Response: fmt.Sprintf("Meta %s: %s", metaType, match[1]),
				})
			}
		}
	}
}

// INFO-04: Búsqueda de comentarios expuestos
func (t *InfoGatheringTest) testExposedComments(targetURL string, client HTTPClient, result *TestResult) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := ReadResponseBody(resp)
	if err != nil {
		return
	}

	// Buscar comentarios HTML que puedan contener información sensible
	commentPattern := regexp.MustCompile(`<!--\s*([^>]+)\s*-->`)
	matches := commentPattern.FindAllStringSubmatch(body, -1)

	sensitiveKeywords := []string{"password", "key", "secret", "token", "api", "debug", "test", "todo", "fixme", "hack"}

	for _, match := range matches {
		if len(match) > 1 {
			comment := strings.ToLower(match[1])
			for _, keyword := range sensitiveKeywords {
				if strings.Contains(comment, keyword) {
					result.Details = append(result.Details, fmt.Sprintf("Comentario sensible encontrado: %s", match[1]))
					result.Evidence = append(result.Evidence, Evidence{
						Type:     "Exposed Comment",
						URL:      targetURL,
						Response: fmt.Sprintf("Comment: %s", match[1]),
					})
					break
				}
			}
		}
	}
}

// INFO-05: Detección de rutas comunes
func (t *InfoGatheringTest) testCommonPaths(targetURL string, client HTTPClient, result *TestResult) {
	commonPaths := []string{
		"/robots.txt",
		"/sitemap.xml",
		"/.well-known/security.txt",
		"/humans.txt",
		"/crossdomain.xml",
		"/clientaccesspolicy.xml",
	}

	baseURL := strings.TrimSuffix(targetURL, "/")

	for _, path := range commonPaths {
		fullURL := baseURL + path

		// Crear request con timeout corto para no demorar mucho
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}

		// Usar un client con timeout corto
		quickClient := &http.Client{Timeout: 3 * time.Second}
		resp, err := quickClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			result.Details = append(result.Details, fmt.Sprintf("Archivo encontrado: %s (Status: %d)", path, resp.StatusCode))
			result.Evidence = append(result.Evidence, Evidence{
				Type:     "Common Path Found",
				URL:      fullURL,
				Response: fmt.Sprintf("HTTP %d - File accessible", resp.StatusCode),
			})
		}
	}
}

// DirectoryEnumerationTest - INFO-06: Directory Enumeration
type DirectoryEnumerationTest struct{}

func (t *DirectoryEnumerationTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "INFO-06: Directory Enumeration",
		Description: "Enumeración de directorios y archivos comunes",
	}

	var details []string
	var evidence []Evidence

	// Lista de directorios/archivos comunes a verificar
	commonPaths := []string{
		"/admin", "/administrator", "/wp-admin", "/phpmyadmin",
		"/config", "/backup", "/test", "/temp", "/uploads",
		"/.git", "/.svn", "/.env", "/config.php", "/web.config",
	}

	for _, path := range commonPaths {
		resp, err := client.Get(targetURL + path)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if (resp.StatusCode == 200 || resp.StatusCode == 403) && resp.StatusCode != 429 {
			details = append(details, fmt.Sprintf("Directorio/archivo encontrado: %s (Status: %d)", path, resp.StatusCode))

			if resp.StatusCode == 200 {
				evidence = append(evidence, Evidence{
					Type:        "Information Disclosure",
					URL:         targetURL + path,
					StatusCode:  resp.StatusCode,
					Description: fmt.Sprintf("Directorio/archivo sensible accesible: %s", path),
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
		result.Severity = "Medium"
	}

	return result
}

// HTTPMethodsTest - INFO-07: HTTP Methods Testing
type HTTPMethodsTest struct{}

func (t *HTTPMethodsTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "INFO-07: HTTP Methods Testing",
		Description: "Prueba de métodos HTTP habilitados",
	}

	var details []string
	var evidence []Evidence

	// Métodos HTTP a probar
	methods := []string{"OPTIONS", "TRACE", "TRACK", "DELETE", "PUT", "PATCH"}

	for _, method := range methods {
		req, err := http.NewRequest(method, targetURL, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 405 && resp.StatusCode != 501 && resp.StatusCode != 429 {
			details = append(details, fmt.Sprintf("Método %s habilitado (Status: %d)", method, resp.StatusCode))

			if method == "TRACE" || method == "TRACK" {
				evidence = append(evidence, Evidence{
					Type:        "HTTP Methods",
					URL:         targetURL,
					StatusCode:  resp.StatusCode,
					Description: fmt.Sprintf("Método HTTP peligroso habilitado: %s", method),
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
		result.Severity = "Medium"
	}

	return result
}
