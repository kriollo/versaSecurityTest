package tests

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func findDetail(details []string, substr string) bool {
	for _, d := range details {
		if strings.Contains(d, substr) {
			return true
		}
	}
	return false
}

// Servidor que reproduce las cuatro fallas: config expuesta, cookie-arreglo 500, SSTI y .php como texto.
func vulnerableServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/versaWYS/config/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"database":{"password":"secreto"}}`))
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("APP_KEY=x")) })
	mux.HandleFunc("/uploads/test.php", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<?php echo 1; ?>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Cookie"), "[]") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Refleja el parámetro ya "evaluado", como un SSTI real
		q := r.URL.Query().Get("q")
		w.Write([]byte(strings.NewReplacer("{{7*7}}", "49", "${7*7}", "49", "#{7*7}", "49").Replace(q)))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// Servidor seguro: todo lo sensible responde 404 y no evalúa plantillas ni se cae con cookies raras.
func safeServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>ok " + r.URL.Query().Get("q") + "</html>"))
	})
	srv := httptest.NewServer(mux) // todo lo demás = 404
	t.Cleanup(srv.Close)
	return srv
}

func TestKnownVulnsDetectaAppVulnerable(t *testing.T) {
	srv := vulnerableServer(t)
	res := (&KnownVulnerabilitiesTest{}).Run(srv.URL, NewBasicHTTPClient(), nil)

	if res.Status != "Failed" || res.Severity != "Critical" {
		t.Fatalf("esperaba Failed/Critical, got %s/%s: %+v", res.Status, res.Severity, res.Details)
	}
	for _, want := range []string{"config.json", "/.env", "arreglo", "plantilla", "código PHP"} {
		if !findDetail(res.Details, want) {
			t.Errorf("no detectó %q en %v", want, res.Details)
		}
	}
}

func TestKnownVulnsNoFalsosPositivosEnAppSegura(t *testing.T) {
	srv := safeServer(t)
	res := (&KnownVulnerabilitiesTest{}).Run(srv.URL, NewBasicHTTPClient(), nil)

	if res.Status != "Passed" || res.Severity != "None" {
		t.Fatalf("app segura marcada como vulnerable: %s/%s %+v", res.Status, res.Severity, res.Details)
	}
}
