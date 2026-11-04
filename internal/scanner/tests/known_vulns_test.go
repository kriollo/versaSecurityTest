package tests

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// checkWordPress debe detectar xmlrpc.php (antes leía el body ya cerrado y nunca lo marcaba).
func TestWordPressXmlrpcSeDetecta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/xmlrpc.php" {
			w.Write([]byte("XML-RPC server accepts POST requests only."))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res := &TestResult{Severity: "None"}
	issues := []string{}
	(&KnownVulnerabilitiesTest{}).checkWordPress(srv.URL, NewBasicHTTPClient(), res, &issues)

	if !findDetail(issues, "xmlrpc.php") {
		t.Fatalf("no detectó xmlrpc.php: %+v", issues)
	}
}

// Rate limit evadible: bloquea por identidad fija, pero si llega una IP nueva en cabecera, responde 200.
func TestRateLimitBypassSeDetecta(t *testing.T) {
	var mu sync.Mutex
	hitsPerIP := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.Header.Get("X-Forwarded-For")
		mu.Lock()
		hitsPerIP[ip]++
		n := hitsPerIP[ip]
		mu.Unlock()
		if n > 10 { // límite POR IP de cabecera → rotarla lo evade
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := &TestResult{Severity: "None"}
	issues := []string{}
	(&KnownVulnerabilitiesTest{}).checkRateLimitBypass(srv.URL, NewBasicHTTPClient(), res, &issues)
	if !findDetail(issues, "Rate limit evadible") {
		t.Fatalf("debía detectar el bypass: %+v", issues)
	}
}

// Rate limit NO evadible: bloquea globalmente sin importar la IP de cabecera → sin hallazgo.
func TestRateLimitBypassNoFalsoPositivo(t *testing.T) {
	var mu sync.Mutex
	total := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		total++
		n := total
		mu.Unlock()
		if n > 10 { // límite global: ignora cabeceras de IP
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := &TestResult{Severity: "None"}
	issues := []string{}
	(&KnownVulnerabilitiesTest{}).checkRateLimitBypass(srv.URL, NewBasicHTTPClient(), res, &issues)
	if findDetail(issues, "Rate limit evadible") {
		t.Fatalf("falso positivo: el límite es global, no evadible: %+v", issues)
	}
}

func TestWordPressEnumeraPluginsConVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-content/plugins/contact-form-7/readme.txt" {
			w.Write([]byte("=== Contact Form 7 ===\nStable tag: 5.7.1\nContributors: ...\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res := &TestResult{Severity: "None"}
	issues := []string{}
	(&KnownVulnerabilitiesTest{}).checkWordPress(srv.URL, NewBasicHTTPClient(), res, &issues)
	if !findDetail(issues, "contact-form-7") || !findDetail(issues, "v5.7.1") {
		t.Fatalf("debía enumerar el plugin y su versión: %+v", issues)
	}
}

func TestNoSQLInjectionSeDetecta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "$ne") || strings.Contains(r.URL.RawQuery, "%24ne") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("MongoError: unknown operator: $ne"))
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	res := &TestResult{Severity: "None"}
	issues := []string{}
	(&KnownVulnerabilitiesTest{}).checkNoSQLInjection(srv.URL, NewBasicHTTPClient(), res, &issues)
	if !findDetail(issues, "NoSQL") {
		t.Fatalf("debía detectar NoSQL injection: %+v", issues)
	}
}

func TestNoSQLInjectionSinFalsoPositivo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>busqueda sin resultados</body></html>"))
	}))
	defer srv.Close()
	res := &TestResult{Severity: "None"}
	issues := []string{}
	(&KnownVulnerabilitiesTest{}).checkNoSQLInjection(srv.URL, NewBasicHTTPClient(), res, &issues)
	if len(issues) != 0 {
		t.Fatalf("falso positivo NoSQL: %+v", issues)
	}
}

func TestXPathInjectionSeDetecta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "1%3D1") || strings.Contains(r.URL.RawQuery, "or") {
			w.Write([]byte("Warning: SimpleXMLElement::xpath(): Invalid expression"))
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	res := &TestResult{Severity: "None"}
	issues := []string{}
	(&KnownVulnerabilitiesTest{}).checkXPathInjection(srv.URL, NewBasicHTTPClient(), res, &issues)
	if !findDetail(issues, "XPath") {
		t.Fatalf("debía detectar XPath injection: %+v", issues)
	}
}

func TestFrameworkSurfacesDetectaSpringYGo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/actuator/env":
			w.Write([]byte(`{"propertySources":[{"name":"systemEnvironment"}]}`))
		case "/debug/pprof/":
			w.Write([]byte("Types of profiles available:\ngoroutine"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	res := &TestResult{Severity: "None"}
	issues := []string{}
	(&KnownVulnerabilitiesTest{}).checkFrameworkSurfaces(srv.URL, NewBasicHTTPClient(), res, &issues)
	if !findDetail(issues, "Spring") || !findDetail(issues, "pprof") {
		t.Fatalf("debía detectar Spring env y Go pprof: %+v", issues)
	}
	if res.Severity != "Critical" { // /actuator/env es Critical
		t.Fatalf("severidad esperada Critical, fue %s", res.Severity)
	}
}

func TestFrameworkSurfacesSinFalsoPositivo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>app normal</body></html>")) // 200 a todo, sin firmas
	}))
	defer srv.Close()
	res := &TestResult{Severity: "None"}
	issues := []string{}
	(&KnownVulnerabilitiesTest{}).checkFrameworkSurfaces(srv.URL, NewBasicHTTPClient(), res, &issues)
	if len(issues) != 0 {
		t.Fatalf("falso positivo en superficies: %+v", issues)
	}
}
