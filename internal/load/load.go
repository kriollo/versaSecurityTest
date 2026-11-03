// Package load es la prueba de capacidad: usuarios virtuales concurrentes, cada uno con sus cookies,
// su usuario y su IP (X-Forwarded-For), que inician sesión y recorren rutas mientras la carga sube
// por etapas. Por etapa reporta peticiones por segundo, latencias p50/p95/p99 y errores.
package load

import (
	"context"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Stage es una etapa: VUs usuarios simultáneos durante Duration.
type Stage struct {
	VUs      int
	Duration time.Duration
}

// Path es una ruta a visitar. XHR la pide como lo hace el frontend (JSON, X-Requested-With).
type Path struct {
	URL string
	XHR bool
}

// Credential es un usuario de prueba.
type Credential struct {
	Email    string
	Password string
}

// Options configura la prueba.
type Options struct {
	BaseURL   string
	Stages    []Stage
	Paths     []Path
	Users     []Credential // vacío: sin login
	LoginPage string       // página que trae el token CSRF del formulario
	LoginPath string       // endpoint al que se envía el formulario
	SpoofIP   bool         // una IP distinta por usuario en X-Forwarded-For
	Think     time.Duration
	Timeout   time.Duration
	Insecure  bool
}

// StageResult son las métricas de una etapa.
type StageResult struct {
	VUs        int            `json:"vus"`
	Duration   time.Duration  `json:"duration_ns"`
	Requests   int            `json:"requests"`
	Errors     int            `json:"errors"`
	ErrorRate  float64        `json:"error_rate"`
	RPS        float64        `json:"rps"`
	P50        time.Duration  `json:"p50_ns"`
	P95        time.Duration  `json:"p95_ns"`
	P99        time.Duration  `json:"p99_ns"`
	Max        time.Duration  `json:"max_ns"`
	Logins     int            `json:"logins"`
	LoginFails int            `json:"login_fails"`
	Status     map[string]int `json:"status"` // "200", "401", "error de red"...
}

var csrfPatterns = []*regexp.Regexp{
	regexp.MustCompile(`name=["']_?csrf_token["'][^>]*value=["']([^"']+)["']`),
	regexp.MustCompile(`value=["']([^"']+)["'][^>]*name=["']_?csrf_token["']`),
	regexp.MustCompile(`<meta[^>]+name=["']csrf-token["'][^>]+content=["']([^"']+)["']`),
}

// ParseStages lee "10:30s,50:1m": usuarios:duración por etapa.
func ParseStages(spec string) ([]Stage, error) {
	var stages []Stage
	for _, part := range strings.Split(spec, ",") {
		vus, dur, ok := strings.Cut(strings.TrimSpace(part), ":")
		n, err := strconv.Atoi(vus)
		d, errD := time.ParseDuration(dur)
		if !ok || err != nil || errD != nil || n < 1 || d <= 0 {
			return nil, fmt.Errorf("etapa inválida %q: se espera usuarios:duración, como 50:30s", part)
		}
		stages = append(stages, Stage{VUs: n, Duration: d})
	}
	return stages, nil
}

// ParsePaths lee "/admin/dashboard,xhr:/api/lista": el prefijo xhr: la pide como el frontend.
func ParsePaths(spec string) []Path {
	var paths []Path
	for _, p := range strings.Split(spec, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(p, "xhr:"); ok {
			paths = append(paths, Path{URL: rest, XHR: true})
		} else {
			paths = append(paths, Path{URL: p})
		}
	}
	return paths
}

// LoadUsers lee un CSV email,password (con o sin encabezado), como el de `app:user:load` de versaWYS.
func LoadUsers(file string) ([]Credential, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	var users []Credential
	for _, r := range rows {
		if len(r) < 2 || r[0] == "email" {
			continue
		}
		users = append(users, Credential{Email: r[0], Password: r[1]})
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("%s no trae usuarios (email,password)", file)
	}
	return users, nil
}

type collector struct {
	mu         sync.Mutex
	latencies  []time.Duration
	status     map[string]int
	errors     int
	logins     atomic.Int64
	loginFails atomic.Int64
}

func (c *collector) add(d time.Duration, status string, failed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.latencies = append(c.latencies, d)
	c.status[status]++
	if failed {
		c.errors++
	}
}

// Run ejecuta las etapas en orden. progress recibe una línea por etapa terminada (puede ser nil).
func Run(ctx context.Context, opts Options, progress func(StageResult)) ([]StageResult, error) {
	if len(opts.Paths) == 0 {
		return nil, fmt.Errorf("indica al menos una ruta a visitar")
	}
	base, err := url.Parse(strings.TrimRight(opts.BaseURL, "/"))
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("URL inválida: %s", opts.BaseURL)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}

	// Un solo transporte compartido, con conexiones suficientes para todos los usuarios
	maxVUs := 0
	for _, s := range opts.Stages {
		maxVUs = max(maxVUs, s.VUs)
	}
	transport := &http.Transport{
		MaxIdleConns:        maxVUs * 2,
		MaxIdleConnsPerHost: maxVUs * 2,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.Insecure}, //nolint:gosec // opción explícita
	}
	defer transport.CloseIdleConnections()

	var results []StageResult
	vuSeq := 0
	for _, stage := range opts.Stages {
		if ctx.Err() != nil {
			break
		}
		c := &collector{status: map[string]int{}}
		stageCtx, cancel := context.WithTimeout(ctx, stage.Duration)
		var wg sync.WaitGroup
		start := time.Now()
		for i := 0; i < stage.VUs; i++ {
			vuSeq++
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				runVU(stageCtx, opts, base, transport, id, c)
			}(vuSeq)
		}
		wg.Wait()
		cancel()
		r := summarize(stage, time.Since(start), c)
		results = append(results, r)
		if progress != nil {
			progress(r)
		}
	}
	return results, nil
}

func runVU(ctx context.Context, opts Options, base *url.URL, transport http.RoundTripper, id int, c *collector) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   opts.Timeout,
		// Un 302 al login significa que la sesión se perdió: se cuenta, no se sigue
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	vu := &virtualUser{opts: opts, base: base, client: client, c: c}
	if opts.SpoofIP {
		// 10.x.y.z único por usuario: el servidor (con trusted_proxies) lo ve como otro cliente
		vu.ip = fmt.Sprintf("10.%d.%d.%d", (id>>16)&255, (id>>8)&255, id&255)
	}

	if len(opts.Users) > 0 {
		cred := opts.Users[(id-1)%len(opts.Users)]
		if !vu.login(ctx, cred) {
			c.loginFails.Add(1)
			return
		}
		c.logins.Add(1)
	}

	for ctx.Err() == nil {
		for _, p := range opts.Paths {
			if ctx.Err() != nil {
				return
			}
			vu.visit(ctx, p)
			if opts.Think > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(opts.Think):
				}
			}
		}
	}
}

type virtualUser struct {
	opts   Options
	base   *url.URL
	client *http.Client
	ip     string
	c      *collector
}

func (vu *virtualUser) request(ctx context.Context, method, path string, xhr bool, body io.Reader, contentType string) (int, string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, method, vu.base.String()+path, body)
	if err != nil {
		return 0, "", 0, err
	}
	req.Header.Set("User-Agent", "versaSecurity-load")
	if vu.ip != "" {
		req.Header.Set("X-Forwarded-For", vu.ip)
	}
	if xhr {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.Header.Set("Accept", "application/json")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	start := time.Now()
	resp, err := vu.client.Do(req)
	if err != nil {
		return 0, "", time.Since(start), err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, string(data), time.Since(start), nil
}

// login: pide la página del formulario (cookie de sesión y token CSRF) y envía las credenciales.
func (vu *virtualUser) login(ctx context.Context, cred Credential) bool {
	status, page, d, err := vu.request(ctx, http.MethodGet, vu.opts.LoginPage, false, nil, "")
	vu.record(d, status, err)
	if err != nil || status != http.StatusOK {
		return false
	}
	form := url.Values{"email": {cred.Email}, "password": {cred.Password}}
	for _, re := range csrfPatterns {
		if m := re.FindStringSubmatch(page); m != nil {
			form.Set("_csrf_token", m[1])
			break
		}
	}
	status, body, d, err := vu.request(ctx, http.MethodPost, vu.opts.LoginPath, true, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	vu.record(d, status, err)
	compact := strings.ReplaceAll(body, " ", "")
	return err == nil && status == http.StatusOK && !strings.Contains(compact, `"success":0`) && !strings.Contains(compact, `"success":false`)
}

func (vu *virtualUser) visit(ctx context.Context, p Path) {
	status, _, d, err := vu.request(ctx, http.MethodGet, p.URL, p.XHR, nil, "")
	if ctx.Err() != nil && err != nil {
		return // la etapa terminó a mitad de la petición: no es un error del servidor
	}
	vu.record(d, status, err)
}

func (vu *virtualUser) record(d time.Duration, status int, err error) {
	switch {
	case err != nil:
		vu.c.add(d, "error de red", true)
	default:
		vu.c.add(d, strconv.Itoa(status), status >= 300)
	}
}

func summarize(stage Stage, elapsed time.Duration, c *collector) StageResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	sort.Slice(c.latencies, func(i, j int) bool { return c.latencies[i] < c.latencies[j] })
	pct := func(p float64) time.Duration {
		if len(c.latencies) == 0 {
			return 0
		}
		return c.latencies[min(len(c.latencies)-1, int(float64(len(c.latencies))*p))]
	}
	r := StageResult{
		VUs:        stage.VUs,
		Duration:   elapsed,
		Requests:   len(c.latencies),
		Errors:     c.errors,
		P50:        pct(0.50),
		P95:        pct(0.95),
		P99:        pct(0.99),
		Max:        pct(1),
		Logins:     int(c.logins.Load()),
		LoginFails: int(c.loginFails.Load()),
		Status:     c.status,
	}
	if r.Requests > 0 {
		r.ErrorRate = float64(r.Errors) / float64(r.Requests)
		r.RPS = float64(r.Requests) / elapsed.Seconds()
	}
	return r
}

// Capacity es la etapa más alta que cumplió los umbrales (errores y p95); -1 si ninguna.
func Capacity(results []StageResult, maxErrorRate float64, maxP95 time.Duration) int {
	best := -1
	for i, r := range results {
		if r.Requests == 0 || r.ErrorRate > maxErrorRate || r.P95 > maxP95 || r.LoginFails > 0 {
			break
		}
		best = i
	}
	return best
}
