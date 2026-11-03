package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMatchSQLError(t *testing.T) {
	// Un error de base de datos real sí coincide
	if _, ok := matchSQLError("You have an error in your SQL syntax; check the manual"); !ok {
		t.Error("debería detectar el error de sintaxis de MySQL")
	}
	// Una página normal que apenas menciona 'sql' NO coincide (era el falso positivo del reporte)
	for _, body := range []string{
		`<!DOCTYPE html><html lang="es"><head><title>404</title></head><body>No encontrado</body></html>`,
		`<html><script src="/app.sql.chunk.js"></script></html>`,
		`consulta tu administrador`,
		`PostgreSQL es una base de datos`, /* menciona el nombre, no es un error */
	} {
		if sig, ok := matchSQLError(body); ok {
			t.Errorf("falso positivo con %q (coincidió %q)", body, sig)
		}
	}
}

// Reproduce el caso del reporte: ?id=1' devuelve un 404 HTML que no es un error SQL → sin hallazgo.
func TestSQLInjectionNoMarcaUn404Normal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"></head><body>Página no encontrada</body></html>`))
	}))
	defer srv.Close()

	res := (&SQLInjectionTest{}).Run(srv.URL, NewBasicHTTPClient(), nil)
	if res.Status == "Failed" {
		t.Fatalf("un 404 normal no debe marcarse como inyección SQL: %+v", res.Details)
	}
}

// Un error de base de datos real en la respuesta sí debe marcarse.
func TestSQLInjectionDetectaErrorRealDeBD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Error: You have an error in your SQL syntax near '''"))
	}))
	defer srv.Close()

	res := (&SQLInjectionTest{}).Run(srv.URL, NewBasicHTTPClient(), nil)
	if res.Status != "Failed" || res.Severity != "High" || len(res.Evidence) == 0 {
		t.Fatalf("un error SQL real debe marcarse: %+v", res)
	}
}
