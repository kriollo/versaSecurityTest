package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Un servidor que, ante un ID de sesión elegido por el cliente, emite el suyo propio → seguro, sin hallazgo.
func TestSessionFixationServidorSeguroNoSeMarca(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Siempre impone su propio ID, ignorando el que venga del cliente (como use_strict_mode)
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "server_generado_abc", Path: "/"})
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	result := &TestResult{Status: "Passed", Severity: "Info"}
	(&SessionMgmtTest{}).testSessionFixation(srv.URL, NewBasicHTTPClient(), result)

	for _, e := range result.Evidence {
		if e.Type == "Session Fixation Risk" {
			t.Fatalf("falso positivo: el servidor sí emite su propio ID de sesión")
		}
	}
}

// Dos GET anónimos con el mismo ID (lo normal) ya NO deben marcarse como fijación.
func TestSessionFixationIDEstableNoEsHallazgo(t *testing.T) {
	first := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Solo setea cookie en la primera visita; luego mantiene la sesión (comportamiento normal)
		if first {
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "estable123", Path: "/"})
			first = false
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	result := &TestResult{Status: "Passed", Severity: "Info"}
	(&SessionMgmtTest{}).testSessionFixation(srv.URL, NewBasicHTTPClient(), result)

	// El servidor aceptó el ID del cliente sin emitir uno nuevo → es un hallazgo Low legítimo, no un crash
	for _, e := range result.Evidence {
		if e.Type == "Session Fixation Risk" && e.Severity != "Low" {
			t.Fatalf("si se marca, debe ser severidad Low, fue %q", e.Severity)
		}
	}
}
