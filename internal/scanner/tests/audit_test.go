package tests

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Cubre los casos de revisar.txt y verifica que los tests detectan lo que dicen, sin falsos positivos.

func TestExtractHost(t *testing.T) {
	cases := map[string]string{
		"https://ejemplo.cl/admin/login": "ejemplo.cl",
		"http://10.0.0.5:8080/":          "10.0.0.5",
		"https://sub.dominio.com:443":    "sub.dominio.com",
		"ejemplo.cl":                     "ejemplo.cl",
	}
	for in, want := range cases {
		if got := extractHost(in); got != want {
			t.Errorf("extractHost(%q) = %q, quería %q", in, got, want)
		}
	}
}

func TestGetServiceNameYContainsVersion(t *testing.T) {
	if getServiceName(3306) != "MySQL" || getServiceName(6379) != "Redis" || getServiceName(9999) != "Unknown" {
		t.Error("getServiceName no mapea puertos conocidos")
	}
	for _, v := range []string{"nginx/1.24.0", "PHP/8.3.1", "Apache 2.4"} {
		if !containsVersion(v) {
			t.Errorf("containsVersion(%q) debería ser true", v)
		}
	}
	for _, v := range []string{"nginx", "Apache", ""} {
		if containsVersion(v) {
			t.Errorf("containsVersion(%q) debería ser false", v)
		}
	}
}

// DataIntegrityTest detecta serialización PHP insegura en cookies (revisar.txt #2).
func TestDataIntegrityDetectaSerializacionPHP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "user", Value: url.QueryEscape(`O:4:"User":1:{s:4:"role";s:5:"admin";}`)})
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res := (&DataIntegrityTest{}).Run(srv.URL, NewBasicHTTPClient(), nil)
	if res.Status != "Warning" || res.Severity != "High" {
		t.Fatalf("no detectó la serialización PHP: %s/%s %+v", res.Status, res.Severity, res.Details)
	}

	// Sin cookie serializada no debe marcar nada
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc123def456"})
		w.Write([]byte("ok"))
	}))
	defer safe.Close()
	if r := (&DataIntegrityTest{}).Run(safe.URL, NewBasicHTTPClient(), nil); len(r.Evidence) != 0 {
		t.Fatalf("falso positivo de serialización: %+v", r.Details)
	}
}

// OutdatedComponentsTest: solo marca un componente si el cuerpo trae el patrón, no por un 200 cualquiera
// (revisar.txt #4 y corrección del falso positivo en catch-all).
func TestOutdatedComponentsExigeElPatronEnElCuerpo(t *testing.T) {
	// Catch-all que responde 200 HTML a todo: no debe reportar WordPress/Drupal/phpMyAdmin
	catchAll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>app</body></html>"))
	}))
	defer catchAll.Close()
	if r := (&OutdatedComponentsTest{}).Run(catchAll.URL, NewBasicHTTPClient(), nil); r.Status == "Warning" {
		t.Fatalf("falso positivo de fingerprint en un catch-all: %+v", r.Details)
	}

	// Servidor que sí sirve el patrón de WordPress en su ruta
	wp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "wp-embed") {
			w.Write([]byte("/*! This file is part of WordPress */"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer wp.Close()
	r := (&OutdatedComponentsTest{}).Run(wp.URL, NewBasicHTTPClient(), nil)
	if !findDetail(r.Details, "wp-embed") {
		t.Fatalf("no detectó WordPress cuando el patrón sí estaba: %+v", r.Details)
	}
}

// AuthenticationTest en un objetivo local (httptest = 127.0.0.1): HTTP NO se marca como inseguro
// (no expone credenciales fuera del equipo), y /admin (login propio) tampoco es un hallazgo.
func TestAuthenticationLocalNoMarcaHTTPniAdmin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" { // login propio: 200
			w.Write([]byte(`<form><input type="password"></form>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res := (&AuthenticationTest{}).Run(srv.URL, NewBasicHTTPClient(), nil)
	if res.Severity == "High" {
		t.Fatalf("en localhost no debe marcar HTTP como riesgo alto: %+v", res.Details)
	}
	for _, d := range res.Details {
		if strings.Contains(d, "HTTP. Las credenciales pueden ser interceptadas") {
			t.Fatalf("en localhost no debe advertir transporte inseguro: %q", d)
		}
	}
	if findDetail(res.Details, "Panel de Administración") {
		t.Fatalf("/admin no debería marcarse como panel expuesto: %+v", res.Details)
	}
}
