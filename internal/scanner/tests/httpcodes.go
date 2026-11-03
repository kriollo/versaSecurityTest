package tests

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// looksLikeAuthPage: la respuesta es una pantalla de login/autenticación (el recurso está protegido y te
// pide iniciar sesión), no el contenido protegido en sí. Un 200 así en /admin NO es un bypass.
func looksLikeAuthPage(body string) bool {
	b := strings.ToLower(body)
	if strings.Contains(b, `type="password"`) || strings.Contains(b, "type='password'") {
		return true
	}
	hints := []string{"iniciar sesión", "iniciar sesion", "login", "log in", "sign in",
		"autenticación", "autenticacion", "ingresar", "contraseña", "password"}
	for _, h := range hints {
		if strings.Contains(b, h) {
			return true
		}
	}
	return false
}

// Interpretación unificada de códigos HTTP, para que todos los tests "lean" lo mismo.

// IsRateLimited: el servidor frenó al escáner (429, o 503 con Retry-After). La respuesta no dice nada
// sobre el recurso: tratarla como hallazgo (endpoint existe, bypass, etc.) es un falso positivo.
func IsRateLimited(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable
}

// IsAccessible: el servidor sirvió el recurso (2xx). Un recurso "accesible" de verdad.
func IsAccessible(code int) bool {
	return code >= 200 && code < 300
}

// IsAuthBlocked: el servidor exige credenciales o las rechaza (401/403). El recurso existe pero está protegido.
func IsAuthBlocked(code int) bool {
	return code == http.StatusUnauthorized || code == http.StatusForbidden
}

// IsNotFound: el recurso no existe o no se maneja (404/410).
func IsNotFound(code int) bool {
	return code == http.StatusNotFound || code == http.StatusGone
}

// Backoff ante 429: así un test que dispara el rate limiter (fuerza bruta, API) no deja la web bloqueada
// para los demás. Se respeta Retry-After si viene; si no, espera creciente y acotada.
const (
	maxRetriesOn429 = 3
	baseBackoff     = 2 * time.Second
	maxBackoff      = 15 * time.Second
)

// retryAfter devuelve cuánto esperar antes de reintentar: el header Retry-After (segundos) si existe y es
// razonable, o el backoff propuesto en su defecto.
func retryAfter(resp *http.Response, fallback time.Duration) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			d := time.Duration(secs) * time.Second
			if d > maxBackoff {
				return maxBackoff // no esperar minutos: si el bloqueo es largo, el test lo marcará como inconcluso
			}
			return d
		}
	}
	return fallback
}
