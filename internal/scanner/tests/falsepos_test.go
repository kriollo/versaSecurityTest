package tests

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// /admin que devuelve el formulario de login (200) NO es un bypass de autorización.
func TestAuthorizationNoMarcaLoginComoBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><form><input type="password" name="pass"></form></body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res := (&AuthorizationTest{}).Run(srv.URL, NewBasicHTTPClient(), nil)
	for _, e := range res.Evidence {
		if e.Type == "Authorization Bypass" {
			t.Fatalf("una página de login no debe marcarse como bypass: %s", e.URL)
		}
	}
}

// Un recurso "protegido" que devuelve contenido real (sin login) sí se marca como posible bypass.
func TestAuthorizationMarcaContenidoSinLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><h1>Panel</h1><table>datos sensibles</table></body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res := (&AuthorizationTest{}).Run(srv.URL, NewBasicHTTPClient(), nil)
	found := false
	for _, e := range res.Evidence {
		if e.Type == "Authorization Bypass" {
			found = true
		}
	}
	if !found {
		t.Fatal("contenido protegido servido sin login debería marcarse")
	}
}

// Information Disclosure: palabras comunes no disparan; un stack trace real sí.
func TestInfoDisclosureSoloConFugaReal(t *testing.T) {
	normal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>Panel de administración. Usuario y contraseña. error de validación.</body></html>`))
	}))
	defer normal.Close()
	if res := (&InfoDisclosureTest{}).Run(normal.URL, NewBasicHTTPClient(), nil); res.Status == "Failed" {
		t.Fatalf("palabras comunes no deben marcar fuga: %+v", res.Details)
	}

	leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<b>Fatal error</b>: Uncaught Exception in /var/www/app/index.php stack trace: ...`))
	}))
	defer leak.Close()
	res := (&InfoDisclosureTest{}).Run(leak.URL, NewBasicHTTPClient(), nil)
	if len(res.Details) == 0 || res.Status == "Passed" {
		t.Fatalf("un stack trace real debe marcarse: %+v", res)
	}
}

// HTTP Headers: sobre HTTP no se exige HSTS (pero CSP ausente sí falla).
func TestHeadersNoExigeHSTSsobreHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res := (&HTTPHeadersTest{}).Run(srv.URL, NewBasicHTTPClient(), nil)
	if res.Status != "Passed" {
		t.Fatalf("con CSP/XCTO/XFO presentes y sin HSTS sobre HTTP debería pasar: %+v", res.Details)
	}
	for _, d := range res.Details {
		if strings.Contains(d, "Strict-Transport-Security ausente") {
			t.Fatal("no debe exigir HSTS sobre HTTP")
		}
	}
}
