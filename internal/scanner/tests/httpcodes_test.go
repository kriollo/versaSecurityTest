package tests

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestInterpretacionDeCodigos(t *testing.T) {
	if !IsRateLimited(429) || !IsRateLimited(503) || IsRateLimited(200) {
		t.Error("IsRateLimited")
	}
	if !IsAccessible(200) || !IsAccessible(204) || IsAccessible(301) || IsAccessible(404) {
		t.Error("IsAccessible")
	}
	if !IsAuthBlocked(401) || !IsAuthBlocked(403) || IsAuthBlocked(200) {
		t.Error("IsAuthBlocked")
	}
	if !IsNotFound(404) || IsNotFound(200) {
		t.Error("IsNotFound")
	}
}

// El cliente reintenta tras un 429 (respetando Retry-After) hasta que la web se desbloquea.
func TestClienteReintentaTras429(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= 2 { // las 2 primeras: bloqueado
			w.Header().Set("Retry-After", "0") // 0 = sin espera real, para que el test sea rápido
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := NewBasicHTTPClient().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tras el backoff debería desbloquearse (200), fue %d", resp.StatusCode)
	}
	if hits.Load() != 3 {
		t.Fatalf("esperaba 3 intentos (2 bloqueados + 1 ok), hubo %d", hits.Load())
	}
}

// Si el 429 persiste, el cliente devuelve el 429 (no se cuelga) para que el test lo marque inconcluso.
func TestClienteDevuelve429SiPersiste(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	resp, err := NewBasicHTTPClient().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("esperaba 429 persistente, fue %d", resp.StatusCode)
	}
}
