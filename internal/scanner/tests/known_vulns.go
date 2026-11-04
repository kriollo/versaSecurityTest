package tests

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// KnownVulnerabilitiesTest comprueba si la app expone las fallas conocidas de 2026 en frameworks PHP
// (Laravel, Symfony, WordPress). Son sondas de solo lectura: ninguna modifica datos ni intenta explotar.
// Útil contra apps propias en desarrollo o producción con autorización.
type KnownVulnerabilitiesTest struct{}

// sensitiveFiles son archivos que nunca deberían servirse con 200. Si responden, filtran secretos o código.
var sensitiveFiles = []struct {
	path string
	ref  string
}{
	{"/.env", "variables de entorno (claves, contraseñas)"},
	{"/.git/config", "repositorio Git expuesto"},
	{"/composer.json", "dependencias del backend"},
	{"/composer.lock", "versiones exactas de dependencias"},
	{"/vendor/autoload.php", "carpeta vendor servible"},
	{"/versaWYS/config/config.json", "configuración del panel (claves de BD y sesión)"},
	{"/versaWYS/composer.lock", "dependencias del kernel"},
	{"/package.json", "dependencias del frontend"},
	{"/versaWYS/logs/", "carpeta de logs"},
	{"/.git/HEAD", "repositorio Git expuesto (HEAD)"},
	{"/.svn/entries", "repositorio SVN expuesto"},
	{"/backup.sql", "volcado de base de datos expuesto"},
	{"/dump.sql", "volcado de base de datos expuesto"},
	{"/db.sql", "volcado de base de datos expuesto"},
	{"/config.php.bak", "backup de configuración con credenciales"},
	{"/config.php.old", "backup de configuración con credenciales"},
	{"/.env.bak", "backup de variables de entorno"},
	{"/.env.local", "variables de entorno locales expuestas"},
	{"/phpinfo.php", "phpinfo() expuesto (información del servidor)"},
	{"/info.php", "phpinfo() expuesto (información del servidor)"},
	{"/server-status", "estado del servidor Apache expuesto"},
	{"/server-info", "información del servidor Apache expuesta"},
	{"/swagger.json", "documentación OpenAPI expuesta"},
	{"/openapi.json", "documentación OpenAPI expuesta"},
	{"/api-docs", "documentación de API expuesta"},
	{"/graphql", "endpoint GraphQL expuesto (introspection)"},
}

func (t *KnownVulnerabilitiesTest) Run(targetURL string, client HTTPClient, _ *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "Vulnerabilidades conocidas (CVE 2026, frameworks PHP)",
		Status:      "Passed",
		Description: "No se detectaron las fallas conocidas de 2026 en frameworks PHP.",
		Severity:    "None",
		Details:     []string{},
		Evidence:    []Evidence{},
	}
	base := strings.TrimRight(targetURL, "/")
	var issues []string

	t.checkSensitiveFiles(base, client, &result, &issues)
	t.checkArrayCookie(base, client, &result, &issues)
	t.checkTemplateInjection(base, client, &result, &issues)
	t.checkPhpExecution(base, client, &result, &issues)
	t.checkDirectoryListing(base, client, &result, &issues)
	t.checkExposedGit(base, client, &result, &issues)
	t.checkDebugEndpoints(base, client, &result, &issues)
	t.checkGraphQLIntrospection(base, client, &result, &issues)

	if len(issues) > 0 {
		result.Status = "Failed"
		result.Description = fmt.Sprintf("%d problema(s) de vulnerabilidades conocidas", len(issues))
		result.Details = issues
	}
	return result
}

// checkSensitiveFiles: CVE-2026 clase WordPress / exposición de configuración. Un 200 con contenido = crítico.
func (t *KnownVulnerabilitiesTest) checkSensitiveFiles(base string, client HTTPClient, result *TestResult, issues *[]string) {
	for _, f := range sensitiveFiles {
		resp, err := client.Get(base + f.path)
		if err != nil {
			continue
		}
		body, _ := ReadResponseBody(resp)
		resp.Body.Close()
		// Un 200 cuyo cuerpo es la página HTML de la app es un catch-all (SPA), no el archivo crudo
		if resp.StatusCode == http.StatusOK && len(strings.TrimSpace(body)) > 0 && !looksLikeHTMLPage(body) {
			*issues = append(*issues, fmt.Sprintf("%s accesible (200): %s", f.path, f.ref))
			if result.Severity != "Critical" {
				result.Severity = "Critical"
			}
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "Archivo sensible expuesto",
				URL:         base + f.path,
				StatusCode:  resp.StatusCode,
				Response:    firstLine(body, 120),
				Severity:    "Critical",
				Description: f.ref,
			})
		}
	}
}

// checkArrayCookie: CVE-2026-114509 (TokenGuard de Laravel). Una cookie de auth enviada como arreglo
// (nombre[]=x) no debe provocar un 500. Se prueba con nombres comunes de cookies de sesión/token.
func (t *KnownVulnerabilitiesTest) checkArrayCookie(base string, client HTTPClient, result *TestResult, issues *[]string) {
	for _, name := range []string{"tknHash", "PHPSESSID", "laravel_session", "remember_web", "token", "auth"} {
		req, err := http.NewRequest(http.MethodGet, base+"/", nil)
		if err != nil {
			return
		}
		req.Header.Set("Cookie", name+"[]=x")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		code := resp.StatusCode
		resp.Body.Close()
		if code >= 500 {
			*issues = append(*issues, fmt.Sprintf("La cookie '%s[]' como arreglo provoca %d (CVE-2026-114509, mal manejo de credenciales no-string)", name, code))
			if result.Severity != "Critical" {
				result.Severity = "High"
			}
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "Credencial no-string mal manejada",
				URL:         base + "/",
				Payload:     "Cookie: " + name + "[]=x",
				StatusCode:  code,
				Severity:    "High",
				Description: "Una estructura de datos en una cookie de autenticación rompe la petición",
			})
			return // una cookie basta para confirmarlo
		}
	}
}

// checkTemplateInjection: CVE-2026-46634 (escape del sandbox de Twig). Si un valor reflejado con una
// expresión de plantilla ({{7*7}} o ${7*7}) aparece evaluado (49), la app compila entrada del usuario.
func (t *KnownVulnerabilitiesTest) checkTemplateInjection(base string, client HTTPClient, result *TestResult, issues *[]string) {
	marker := "yx8" // reduce falsos positivos: 49 debe aparecer junto al marcador
	for _, payload := range []string{"{{7*7}}" + marker, "${7*7}" + marker, "#{7*7}" + marker} {
		resp, err := client.Get(base + "/?q=" + payload)
		if err != nil {
			continue
		}
		body, _ := ReadResponseBody(resp)
		resp.Body.Close()
		if strings.Contains(body, "49"+marker) {
			*issues = append(*issues, "Inyección de plantilla del lado servidor: una expresión del usuario se evaluó (CVE-2026-46634)")
			result.Severity = "Critical"
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "Server-Side Template Injection",
				URL:         base + "/?q=" + payload,
				Payload:     payload,
				StatusCode:  resp.StatusCode,
				Severity:    "Critical",
				Description: "7*7 se evaluó como 49: la entrada se compila como plantilla",
			})
			return
		}
	}
}

// checkPhpExecution: CVE-2026-119977 clase WordPress. Un .php fuera del front controller no debería
// ejecutarse ni devolver su código fuente. Se piden rutas típicas de código subido/olvidado.
func (t *KnownVulnerabilitiesTest) checkPhpExecution(base string, client HTTPClient, result *TestResult, issues *[]string) {
	for _, p := range []string{"/uploads/test.php", "/public/uploads/x.php", "/storage/app.php", "/tmp.php"} {
		resp, err := client.Get(base + p)
		if err != nil {
			continue
		}
		body, _ := ReadResponseBody(resp)
		resp.Body.Close()
		// Solo es un hallazgo si el archivo existe (200) y devuelve código PHP sin ejecutar
		if resp.StatusCode == http.StatusOK && strings.Contains(body, "<?php") {
			*issues = append(*issues, fmt.Sprintf("%s devuelve código PHP sin ejecutar: el servidor no procesa ese .php (riesgo de fuga de código)", p))
			if result.Severity == "None" {
				result.Severity = "High"
			}
			result.Evidence = append(result.Evidence, Evidence{
				Type:       "Código PHP servido como texto",
				URL:        base + p,
				StatusCode: resp.StatusCode,
				Response:   firstLine(body, 120),
				Severity:   "High",
			})
		}
	}
}

// checkDirectoryListing: detecta listado de directorios habilitado (Index of /).
func (t *KnownVulnerabilitiesTest) checkDirectoryListing(base string, client HTTPClient, result *TestResult, issues *[]string) {
	for _, p := range []string{"/", "/uploads/", "/images/", "/assets/", "/static/"} {
		resp, err := client.Get(base + p)
		if err != nil {
			continue
		}
		body, _ := ReadResponseBody(resp)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && strings.Contains(strings.ToLower(body), "index of /") {
			*issues = append(*issues, fmt.Sprintf("Listado de directorios habilitado en %s", p))
			result.Severity = "Medium"
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "Directory Listing",
				URL:         base + p,
				StatusCode:  resp.StatusCode,
				Severity:    "Medium",
				Description: "El servidor lista el contenido del directorio",
			})
		}
	}
}

// checkExposedGit: /.git/HEAD expuesto permite descargar el repositorio completo.
func (t *KnownVulnerabilitiesTest) checkExposedGit(base string, client HTTPClient, result *TestResult, issues *[]string) {
	resp, err := client.Get(base + "/.git/HEAD")
	if err != nil {
		return
	}
	body, _ := ReadResponseBody(resp)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK && strings.Contains(body, "ref: refs/heads") {
		*issues = append(*issues, "/.git/HEAD expuesto: el repositorio Git puede descargarse completo")
		result.Severity = "Critical"
		result.Evidence = append(result.Evidence, Evidence{
			Type:        "Repositorio Git expuesto",
			URL:         base + "/.git/HEAD",
			StatusCode:  resp.StatusCode,
			Response:    firstLine(body, 120),
			Severity:    "Critical",
		})
	}
}

// checkDebugEndpoints: endpoints de depuración expuestos.
func (t *KnownVulnerabilitiesTest) checkDebugEndpoints(base string, client HTTPClient, result *TestResult, issues *[]string) {
	for _, p := range []string{"/debug", "/trace", "/_profiler", "/telescope", "/horizon"} {
		resp, err := client.Get(base + p)
		if err != nil {
			continue
		}
		body, _ := ReadResponseBody(resp)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && !looksLikeHTMLPage(body) {
			*issues = append(*issues, fmt.Sprintf("Endpoint de depuración accesible: %s", p))
			if result.Severity != "Critical" {
				result.Severity = "High"
			}
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "Debug Endpoint",
				URL:         base + p,
				StatusCode:  resp.StatusCode,
				Severity:    "High",
			})
		}
	}
}

// checkGraphQLIntrospection: introspection habilitada expone el esquema completo.
func (t *KnownVulnerabilitiesTest) checkGraphQLIntrospection(base string, client HTTPClient, result *TestResult, issues *[]string) {
	for _, p := range []string{"/graphql", "/graphiql", "/playground"} {
		req, err := http.NewRequest(http.MethodPost, base+p, strings.NewReader(`{"query":"{__schema{types{name}}}"}`))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := ReadResponseBody(resp)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && strings.Contains(body, "__schema") {
			*issues = append(*issues, fmt.Sprintf("Introspection de GraphQL habilitada en %s", p))
			if result.Severity != "Critical" {
				result.Severity = "High"
			}
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "GraphQL Introspection",
				URL:         base + p,
				StatusCode:  resp.StatusCode,
				Severity:    "High",
			})
		}
	}
}

// looksLikeHTMLPage: la respuesta es una página web (la app enrutó la petición), no un archivo servido tal cual.
func looksLikeHTMLPage(body string) bool {
	head := strings.ToLower(strings.TrimSpace(body))
	if len(head) > 256 {
		head = head[:256]
	}
	return strings.Contains(head, "<!doctype html") || strings.Contains(head, "<html") || strings.Contains(head, "<head")
}

func firstLine(s string, n int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > n {
		s = s[:n]
	}
	return s
}
