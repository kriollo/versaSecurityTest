package load

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFloodDetectaRateLimit(t *testing.T) {
	// Servidor que frena tras cierto número de peticiones: devuelve 429 (como un rate limiter)
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) > 50 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := RunFlood(context.Background(), FloodOptions{
		BaseURL: srv.URL, Workers: 20, Duration: 300 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.RateLimited == 0 || res.ServerError != 0 {
		t.Fatalf("esperaba 429 y ningún 5xx: %+v", res)
	}
	if !contains(res.Verdict(), "frenó el abuso") {
		t.Fatalf("veredicto inesperado: %s", res.Verdict())
	}
}

func TestFloodDetectaDegradacion(t *testing.T) {
	// Servidor que se rompe bajo carga: siempre 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	res, _ := RunFlood(context.Background(), FloodOptions{
		BaseURL: srv.URL, Workers: 10, Duration: 200 * time.Millisecond,
	}, nil)
	if res.ServerError == 0 || !contains(res.Verdict(), "se rompe") {
		t.Fatalf("debió marcar degradación: %+v / %s", res, res.Verdict())
	}
}

func TestFloodRotaIPDistintaPorPeticion(t *testing.T) {
	ips := &sync.Map{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ips.Store(r.Header.Get("X-Forwarded-For"), true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, _ := RunFlood(context.Background(), FloodOptions{
		BaseURL: srv.URL, Workers: 5, Duration: 200 * time.Millisecond, RotateIP: true,
	}, nil)

	distinct := 0
	ips.Range(func(any, any) bool { distinct++; return true })
	// Cada petición lleva una IP distinta: casi tantas IP como peticiones
	if distinct < res.Requests/2 || distinct < 2 {
		t.Fatalf("se esperaban muchas IP distintas, hubo %d para %d peticiones", distinct, res.Requests)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (stringIndex(s, sub) >= 0) }

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
