package load

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// FloodOptions configura la prueba de resiliencia ante DoS: un flujo intenso desde muchas IP distintas
// para comprobar si el límite de peticiones de TU app lo contiene (responde 429) o si se degrada (5xx,
// timeouts). Es una prueba de defensa, para servidores propios o con autorización.
type FloodOptions struct {
	BaseURL  string
	Path     string
	Workers  int           // peticiones en paralelo
	Duration time.Duration // cuánto dura el flujo
	RotateIP bool          // una IP distinta por petición en X-Forwarded-For (prueba el límite por IP)
	Timeout  time.Duration
	Insecure bool
}

// FloodResult resume el comportamiento del servidor bajo el flujo.
type FloodResult struct {
	Requests    int            `json:"requests"`
	Duration    time.Duration  `json:"duration_ns"`
	RPS         float64        `json:"rps"`
	Status      map[string]int `json:"status"`
	RateLimited int            `json:"rate_limited"` // 429: el servidor frenó el abuso (deseable)
	ServerError int            `json:"server_error"` // 5xx: el servidor se rompió bajo carga
	NetworkErr  int            `json:"network_err"`  // timeouts / conexiones rechazadas
	OK          int            `json:"ok"`           // 2xx/3xx servidos
	P50         time.Duration  `json:"p50_ns"`
	P95         time.Duration  `json:"p95_ns"`
	P99         time.Duration  `json:"p99_ns"`
	Max         time.Duration  `json:"max_ns"`
}

// Verdict describe en una línea si la app aguantó el abuso.
func (r FloodResult) Verdict() string {
	switch {
	case r.Requests == 0:
		return "⚠️  No se completó ninguna petición: ¿servidor caído o inalcanzable?"
	case r.NetworkErr > r.Requests/5:
		return fmt.Sprintf("❌ %d de %d peticiones fallaron en red (timeout/conexión): el servidor no sostiene el ritmo. Revisa límites de FPM/conexiones y rate limiting.", r.NetworkErr, r.Requests)
	case r.ServerError > r.Requests/20:
		return fmt.Sprintf("❌ %d respuestas 5xx bajo carga: la app se rompe en vez de frenar. Revisa rate limiting y manejo de errores.", r.ServerError)
	case r.RateLimited > 0:
		return fmt.Sprintf("✅ El límite de peticiones frenó el abuso: %d respuestas 429 (sin 5xx ni caídas).", r.RateLimited)
	default:
		return "⚠️  La app sirvió todo el flujo sin frenarlo (sin 429). Si esperabas rate limiting, quizá no está activo o las IP rotadas lo evaden; súbele -workers para encontrar el techo."
	}
}

// RunFlood ejecuta el flujo y devuelve el resumen. progress (opcional) recibe un avance cada segundo.
func RunFlood(ctx context.Context, opts FloodOptions, progress func(done int, rps float64)) (FloodResult, error) {
	if opts.BaseURL == "" {
		return FloodResult{}, fmt.Errorf("falta la URL base")
	}
	if opts.Workers < 1 {
		opts.Workers = 50
	}
	if opts.Duration <= 0 {
		opts.Duration = 20 * time.Second
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Path == "" {
		opts.Path = "/"
	}

	transport := &http.Transport{
		MaxIdleConns:        opts.Workers * 2,
		MaxIdleConnsPerHost: opts.Workers * 2,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.Insecure}, //nolint:gosec // opción explícita
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: opts.Timeout}

	c := &collector{status: map[string]int{}}
	var done atomic.Int64
	var ipCounter atomic.Int64
	url := trimSlash(opts.BaseURL) + opts.Path

	runCtx, cancel := context.WithTimeout(ctx, opts.Duration)
	defer cancel()

	if progress != nil {
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			start := time.Now()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-ticker.C:
					n := int(done.Load())
					progress(n, float64(n)/time.Since(start).Seconds())
				}
			}
		}()
	}

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for runCtx.Err() == nil {
				req, err := http.NewRequestWithContext(runCtx, http.MethodGet, url, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "versaSecurity-flood")
				if opts.RotateIP {
					// 10.x.y.z distinta por petición: prueba si el límite por IP se puede evadir rotando origen
					id := ipCounter.Add(1)
					req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.%d.%d.%d", (id>>16)&255, (id>>8)&255, id&255))
				}
				t0 := time.Now()
				resp, err := client.Do(req)
				lat := time.Since(t0)
				if err != nil {
					if runCtx.Err() != nil {
						return // la ventana terminó a mitad de petición: no cuenta como error del servidor
					}
					c.add(lat, "error de red", true)
					done.Add(1)
					continue
				}
				io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
				c.add(lat, strconv.Itoa(resp.StatusCode), resp.StatusCode >= 500)
				done.Add(1)
			}
		}()
	}
	wg.Wait()
	return summarizeFlood(time.Since(start), c), nil
}

func summarizeFlood(elapsed time.Duration, c *collector) FloodResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	sort.Slice(c.latencies, func(i, j int) bool { return c.latencies[i] < c.latencies[j] })
	pct := func(p float64) time.Duration {
		if len(c.latencies) == 0 {
			return 0
		}
		return c.latencies[min(len(c.latencies)-1, int(float64(len(c.latencies))*p))]
	}
	r := FloodResult{
		Requests: len(c.latencies),
		Duration: elapsed,
		Status:   c.status,
		P50:      pct(0.50), P95: pct(0.95), P99: pct(0.99), Max: pct(1),
	}
	for code, n := range c.status {
		switch {
		case code == "error de red":
			r.NetworkErr += n
		case code == "429":
			r.RateLimited += n
		case len(code) == 3 && code[0] == '5':
			r.ServerError += n
		case len(code) == 3 && (code[0] == '2' || code[0] == '3'):
			r.OK += n
		}
	}
	if elapsed > 0 {
		r.RPS = float64(r.Requests) / elapsed.Seconds()
	}
	return r
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
