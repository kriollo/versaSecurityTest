package tests

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Servidor vulnerable a boolean-blind: la condición falsa (1=2 / '1'='2') devuelve una página corta,
// la verdadera devuelve la página completa (como si la consulta se viera afectada).
func boolBlindServer(t *testing.T) *httptest.Server {
	full := "<html><body>" + strings.Repeat("contenido ", 200) + "</body></html>"
	empty := "<html><body>sin resultados</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if strings.Contains(v, "'1'='2'") || strings.Contains(v, "1=2") {
			w.Write([]byte(empty))
			return
		}
		w.Write([]byte(full))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckBlindDetectaBooleano(t *testing.T) {
	srv := boolBlindServer(t)
	ev := (&AdvancedSQLInjectionTest{}).checkBlind(NewBasicHTTPClient(), srv.URL, "", "id")
	if ev == nil {
		t.Fatal("debería detectar boolean-based blind SQLi")
	}
	if !strings.Contains(ev.Response, "Boolean") {
		t.Fatalf("evidencia inesperada: %s", ev.Response)
	}
}

func TestCheckBlindNoFalsoPositivoEnPaginaEstatica(t *testing.T) {
	// Devuelve siempre lo mismo, pase lo que pase: no es inyectable
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>pagina fija</body></html>"))
	}))
	defer srv.Close()
	if ev := (&AdvancedSQLInjectionTest{}).checkBlind(NewBasicHTTPClient(), srv.URL, "", "id"); ev != nil {
		t.Fatalf("falso positivo en página estática: %+v", ev)
	}
}

func TestCheckBlindNoFalsoPositivoEn404(t *testing.T) {
	// Todo responde 404: la base no es 2xx, no se concluye nada
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("<html><body>404</body></html>"))
	}))
	defer srv.Close()
	if ev := (&AdvancedSQLInjectionTest{}).checkBlind(NewBasicHTTPClient(), srv.URL, "", "id"); ev != nil {
		t.Fatalf("falso positivo en 404: %+v", ev)
	}
}
