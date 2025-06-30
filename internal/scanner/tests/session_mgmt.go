package tests

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// SessionMgmtTest implementa tests de gestión de sesiones
type SessionMgmtTest struct{}

// Run ejecuta todos los tests de gestión de sesiones
func (t *SessionMgmtTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "Session Management",
		Status:      "Passed",
		Description: "Gestión de sesiones, tokens, expiración y seguridad de cookies",
		Severity:    "Info",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	// SESS-01: Cookie sin atributo HttpOnly
	t.testCookieHttpOnly(targetURL, client, &result)
	
	// SESS-02: Cookie sin Secure
	t.testCookieSecure(targetURL, client, &result)
	
	// SESS-03: Verificar SameSite
	t.testCookieSameSite(targetURL, client, &result)
	
	// SESS-04: Análisis de tokens JWT
	t.testJWTTokens(targetURL, client, &result)
	
	// SESS-05: Test de fijación de sesión
	t.testSessionFixation(targetURL, client, &result)

	// Determinar el estado final
	if len(result.Details) == 0 {
		result.Description = "Gestión de sesiones configurada correctamente"
	} else {
		result.Status = "Failed"
		result.Description = fmt.Sprintf("Se encontraron %d problemas de gestión de sesiones", len(result.Details))
		result.Severity = "Medium"
	}

	return result
}

// SESS-01: Cookie sin atributo HttpOnly
func (t *SessionMgmtTest) testCookieHttpOnly(targetURL string, client HTTPClient, result *TestResult) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Analizar cookies en las respuestas
	cookies := resp.Cookies()
	
	for _, cookie := range cookies {
		// Verificar si es una cookie de sesión (nombres comunes)
		sessionCookieNames := []string{
			"sessionid", "session_id", "session", "sess", "sid", 
			"jsessionid", "phpsessid", "asp.net_sessionid", 
			"connect.sid", "laravel_session", "ci_session",
			"auth", "token", "jwt", "access_token",
		}
		
		isSessionCookie := false
		cookieNameLower := strings.ToLower(cookie.Name)
		
		for _, sessionName := range sessionCookieNames {
			if strings.Contains(cookieNameLower, sessionName) {
				isSessionCookie = true
				break
			}
		}
		
		if isSessionCookie && !cookie.HttpOnly {
			result.Details = append(result.Details, fmt.Sprintf("Cookie de sesión '%s' sin atributo HttpOnly", cookie.Name))
			result.Evidence = append(result.Evidence, Evidence{
				Type:     "Insecure Cookie",
				URL:      targetURL,
				Response: fmt.Sprintf("Cookie %s missing HttpOnly attribute", cookie.Name),
			})
		}
	}
}

// SESS-02: Cookie sin Secure
func (t *SessionMgmtTest) testCookieSecure(targetURL string, client HTTPClient, result *TestResult) {
	// Solo verificar si es HTTPS
	if !strings.HasPrefix(targetURL, "https://") {
		return
	}
	
	resp, err := client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	
	for _, cookie := range cookies {
		// Verificar si es una cookie importante
		importantCookieNames := []string{
			"sessionid", "session_id", "session", "sess", "sid", 
			"jsessionid", "phpsessid", "asp.net_sessionid", 
			"auth", "token", "jwt", "access_token",
		}
		
		isImportantCookie := false
		cookieNameLower := strings.ToLower(cookie.Name)
		
		for _, importantName := range importantCookieNames {
			if strings.Contains(cookieNameLower, importantName) {
				isImportantCookie = true
				break
			}
		}
		
		if isImportantCookie && !cookie.Secure {
			result.Details = append(result.Details, fmt.Sprintf("Cookie importante '%s' sin atributo Secure en HTTPS", cookie.Name))
			result.Evidence = append(result.Evidence, Evidence{
				Type:     "Insecure Cookie",
				URL:      targetURL,
				Response: fmt.Sprintf("Cookie %s missing Secure attribute on HTTPS", cookie.Name),
			})
		}
	}
}

// SESS-03: Verificar SameSite
func (t *SessionMgmtTest) testCookieSameSite(targetURL string, client HTTPClient, result *TestResult) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Analizar headers Set-Cookie manualmente para SameSite
	setCookieHeaders := resp.Header["Set-Cookie"]
	
	for _, setCookieHeader := range setCookieHeaders {
		// Extraer nombre de la cookie
		parts := strings.Split(setCookieHeader, ";")
		if len(parts) == 0 {
			continue
		}
		
		cookieNameValue := strings.Split(parts[0], "=")
		if len(cookieNameValue) < 2 {
			continue
		}
		
		cookieName := strings.TrimSpace(cookieNameValue[0])
		
		// Verificar si es una cookie de sesión
		sessionCookieNames := []string{
			"sessionid", "session_id", "session", "sess", "sid", 
			"jsessionid", "phpsessid", "asp.net_sessionid", 
			"auth", "token", "jwt", "access_token",
		}
		
		isSessionCookie := false
		cookieNameLower := strings.ToLower(cookieName)
		
		for _, sessionName := range sessionCookieNames {
			if strings.Contains(cookieNameLower, sessionName) {
				isSessionCookie = true
				break
			}
		}
		
		if isSessionCookie {
			// Verificar si tiene SameSite
			hasSameSite := false
			for _, part := range parts {
				if strings.Contains(strings.ToLower(part), "samesite") {
					hasSameSite = true
					break
				}
			}
			
			if !hasSameSite {
				result.Details = append(result.Details, fmt.Sprintf("Cookie de sesión '%s' sin atributo SameSite", cookieName))
				result.Evidence = append(result.Evidence, Evidence{
					Type:     "Missing SameSite Cookie",
					URL:      targetURL,
					Response: fmt.Sprintf("Cookie %s missing SameSite attribute", cookieName),
				})
			}
		}
	}
}

// SESS-04: Análisis de tokens JWT
func (t *SessionMgmtTest) testJWTTokens(targetURL string, client HTTPClient, result *TestResult) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := ReadResponseBody(resp)
	if err != nil {
		return
	}

	// Buscar tokens JWT en el contenido
	
	if strings.Contains(body, "eyJ") {
		// Posible JWT encontrado
		result.Details = append(result.Details, "Posible token JWT encontrado en respuesta HTML")
		result.Evidence = append(result.Evidence, Evidence{
			Type:     "JWT Token Exposure",
			URL:      targetURL,
			Response: "JWT token pattern found in HTML response",
		})
	}
	
	// Verificar headers de autorización
	authHeader := resp.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer eyJ") {
		result.Details = append(result.Details, "Token JWT expuesto en header Authorization")
		result.Evidence = append(result.Evidence, Evidence{
			Type:     "JWT Token in Header",
			URL:      targetURL,
			Response: "JWT token found in Authorization header",
		})
	}
}

// SESS-05: Test de fijación de sesión
func (t *SessionMgmtTest) testSessionFixation(targetURL string, client HTTPClient, result *TestResult) {
	// Crear un cliente HTTP personalizado para mantener cookies
	jar := &SimpleCookieJar{cookies: make(map[string][]*http.Cookie)}
	customClient := &http.Client{
		Jar: jar,
	}
	
	// Primera request para obtener una sesión
	req1, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}
	
	resp1, err := customClient.Do(req1)
	if err != nil {
		return
	}
	resp1.Body.Close()
	
	// Verificar si se estableció una cookie de sesión
	initialCookies := resp1.Cookies()
	var sessionCookie *http.Cookie
	
	for _, cookie := range initialCookies {
		cookieNameLower := strings.ToLower(cookie.Name)
		if strings.Contains(cookieNameLower, "session") || 
		   strings.Contains(cookieNameLower, "sid") ||
		   strings.Contains(cookieNameLower, "sess") {
			sessionCookie = cookie
			break
		}
	}
	
	if sessionCookie == nil {
		return // No hay cookie de sesión para probar
	}
	
	// Segunda request con la misma cookie
	req2, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}
	
	resp2, err := customClient.Do(req2)
	if err != nil {
		return
	}
	resp2.Body.Close()
	
	// Verificar si la cookie de sesión cambió
	newCookies := resp2.Cookies()
	sessionChanged := false
	
	for _, cookie := range newCookies {
		if cookie.Name == sessionCookie.Name && cookie.Value != sessionCookie.Value {
			sessionChanged = true
			break
		}
	}
	
	if !sessionChanged {
		result.Details = append(result.Details, "Posible vulnerabilidad de fijación de sesión - ID de sesión no regenerado")
		result.Evidence = append(result.Evidence, Evidence{
			Type:     "Session Fixation Risk",
			URL:      targetURL,
			Response: "Session ID not regenerated on subsequent requests",
		})
	}
}

// SimpleCookieJar implementa http.CookieJar de forma básica
type SimpleCookieJar struct {
	cookies map[string][]*http.Cookie
}

func (jar *SimpleCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	jar.cookies[u.Host] = cookies
}

func (jar *SimpleCookieJar) Cookies(u *url.URL) []*http.Cookie {
	return jar.cookies[u.Host]
}
