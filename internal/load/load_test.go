package load

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Un servidor como versaWYS: formulario con token CSRF, login que deja una cookie y una API que la exige.
func fakeApp(t *testing.T) (*httptest.Server, *sync.Map, *sync.Map) {
	ips, emails := &sync.Map{}, &sync.Map{}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "s", Path: "/"})
		w.Write([]byte(`<form><input type="hidden" name="_csrf_token" value="tok123"></form>`))
	})
	mux.HandleFunc("/admin/login/autentication", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.PostForm.Get("_csrf_token") != "tok123" || r.PostForm.Get("password") != "Clave#1" {
			w.Write([]byte(`{"success":0}`))
			return
		}
		emails.Store(r.PostForm.Get("email"), true)
		http.SetCookie(w, &http.Cookie{Name: "tknHash", Value: "ok", Path: "/"})
		w.Write([]byte(`{"success":1}`))
	})
	mux.HandleFunc("/admin/api", func(w http.ResponseWriter, r *http.Request) {
		ips.Store(r.Header.Get("X-Forwarded-For"), true)
		if c, err := r.Cookie("tknHash"); err != nil || c.Value != "ok" || r.Header.Get("X-Requested-With") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"data":[]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, ips, emails
}

func count(m *sync.Map) int {
	n := 0
	m.Range(func(any, any) bool { n++; return true })
	return n
}

func TestEachVirtualUserLogsInWithItsOwnUserAndIP(t *testing.T) {
	srv, ips, emails := fakeApp(t)
	users := []Credential{{"a@carga.test", "Clave#1"}, {"b@carga.test", "Clave#1"}, {"c@carga.test", "Clave#1"}}

	results, err := Run(context.Background(), Options{
		BaseURL: srv.URL, Stages: []Stage{{VUs: 3, Duration: 300 * time.Millisecond}, {VUs: 6, Duration: 300 * time.Millisecond}},
		Paths: []Path{{URL: "/admin/api", XHR: true}}, Users: users,
		LoginPage: "/admin/login", LoginPath: "/admin/login/autentication", SpoofIP: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 2 || results[0].VUs != 3 || results[1].VUs != 6 {
		t.Fatalf("etapas: %+v", results)
	}
	for _, r := range results {
		if r.Errors != 0 || r.LoginFails != 0 || r.Logins != r.VUs || r.Requests == 0 || r.P95 <= 0 || r.RPS <= 0 {
			t.Fatalf("etapa con %d usuarios: %+v", r.VUs, r)
		}
	}
	if count(emails) != 3 {
		t.Fatalf("se esperaban los 3 usuarios del CSV, entraron %d", count(emails))
	}
	if count(ips) != 9 { // 3 + 6 usuarios virtuales, cada uno con su IP
		t.Fatalf("se esperaban 9 IP distintas, llegaron %d", count(ips))
	}
	if Capacity(results, 0.01, time.Second) != 1 {
		t.Fatalf("las dos etapas cumplen los umbrales")
	}
}

func TestErrorsAndFailedLoginsAreCountedAndStopTheCapacity(t *testing.T) {
	srv, _, _ := fakeApp(t)

	results, _ := Run(context.Background(), Options{
		BaseURL: srv.URL, Stages: []Stage{{VUs: 2, Duration: 200 * time.Millisecond}},
		Paths: []Path{{URL: "/admin/api", XHR: true}}, Users: []Credential{{"a@carga.test", "mala"}},
		LoginPage: "/admin/login", LoginPath: "/admin/login/autentication",
	}, nil)
	if results[0].LoginFails != 2 || results[0].Logins != 0 {
		t.Fatalf("login con clave mala: %+v", results[0])
	}

	// Sin login, la API responde 401: son errores
	results, _ = Run(context.Background(), Options{
		BaseURL: srv.URL, Stages: []Stage{{VUs: 2, Duration: 200 * time.Millisecond}},
		Paths: []Path{{URL: "/admin/api", XHR: true}},
	}, nil)
	if results[0].Errors == 0 || results[0].Errors != results[0].Status["401"] {
		t.Fatalf("los 401 deben contarse como errores: %+v", results[0])
	}
	if Capacity(results, 0.01, time.Second) != -1 {
		t.Fatalf("una etapa con errores no cuenta como capacidad")
	}
}

func TestParseStagesAndPaths(t *testing.T) {
	stages, err := ParseStages("10:30s, 50:1m")
	if err != nil || len(stages) != 2 || stages[1].VUs != 50 || stages[1].Duration != time.Minute {
		t.Fatalf("%+v %v", stages, err)
	}
	for _, bad := range []string{"", "10", "x:30s", "0:30s", "10:-1s"} {
		if _, err := ParseStages(bad); err == nil {
			t.Fatalf("%q debería ser inválida", bad)
		}
	}
	paths := ParsePaths("/admin/dashboard, xhr:/admin/api,")
	if len(paths) != 2 || paths[0].XHR || !paths[1].XHR || paths[1].URL != "/admin/api" {
		t.Fatalf("%+v", paths)
	}
}
