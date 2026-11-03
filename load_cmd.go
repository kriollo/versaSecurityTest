package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/versaSecurityTest/internal/load"
)

// runLoad es `versaSecurity load -url ...`: la prueba de capacidad.
func runLoad(args []string) int {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	urlFlag := fs.String("url", "", "URL base de la aplicación (obligatoria)")
	stages := fs.String("stages", "10:30s,50:30s,100:30s,200:30s", "Etapas usuarios:duración, separadas por coma")
	paths := fs.String("paths", "/", "Rutas a recorrer; prefijo xhr: para pedirlas como el frontend (JSON)")
	usersFile := fs.String("users-file", "", "CSV email,password (versaWYS: php versaCLI app:user:load --count=N)")
	loginPage := fs.String("login-page", "/admin/login", "Página con el formulario de login (trae el token CSRF)")
	loginPath := fs.String("login-path", "/admin/login/autentication", "Endpoint que recibe el login")
	spoofIP := fs.Bool("spoof-ip", true, "Una IP distinta por usuario en X-Forwarded-For (el servidor debe confiar en el proxy)")
	think := fs.Duration("think", 500*time.Millisecond, "Pausa entre peticiones de un mismo usuario")
	maxP95 := fs.Duration("max-p95", time.Second, "Umbral de p95 para dar por buena una etapa")
	maxErrors := fs.Float64("max-errors", 0.01, "Umbral de tasa de errores para dar por buena una etapa (0.01 = 1%)")
	timeout := fs.Duration("timeout", 30*time.Second, "Timeout por petición")
	insecure := fs.Bool("insecure", false, "No verificar el certificado TLS (entornos de prueba)")
	output := fs.String("output", "", "Archivo JSON del informe (por defecto reports/carga_<fecha>.json)")
	fs.Parse(args)
	target := *urlFlag
	if target == "" {
		fmt.Println("❌ Falta -url. Uso: versaSecurity load -url http://localhost:8000 -users-file carga.csv -paths /admin/dashboard,xhr:/admin/users/getUsersPaginated?page=1")
		fs.PrintDefaults()
		return 1
	}

	st, err := load.ParseStages(*stages)
	if err != nil {
		fmt.Println("❌", err)
		return 1
	}
	opts := load.Options{
		BaseURL: target, Stages: st, Paths: load.ParsePaths(*paths), LoginPage: *loginPage, LoginPath: *loginPath,
		SpoofIP: *spoofIP, Think: *think, Timeout: *timeout, Insecure: *insecure,
	}
	if *usersFile != "" {
		if opts.Users, err = load.LoadUsers(*usersFile); err != nil {
			fmt.Println("❌", err)
			return 1
		}
	}

	fmt.Printf("⚠️  Prueba de carga contra %s: úsala solo en un servidor propio o con autorización.\n", target)
	fmt.Printf("👥 %d etapas, %d usuarios de prueba, rutas: %s\n\n", len(st), len(opts.Users), *paths)
	fmt.Printf("%7s %9s %8s %9s %9s %9s %9s %8s %s\n", "usuarios", "peticiones", "req/s", "p50", "p95", "p99", "máx", "errores", "estados")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	results, err := load.Run(ctx, opts, func(r load.StageResult) {
		fmt.Printf("%7d %9d %8.1f %9s %9s %9s %9s %7.1f%% %s\n", r.VUs, r.Requests, r.RPS,
			ms(r.P50), ms(r.P95), ms(r.P99), ms(r.Max), r.ErrorRate*100, statusLine(r))
	})
	if err != nil {
		fmt.Println("❌", err)
		return 1
	}

	best := load.Capacity(results, *maxErrors, *maxP95)
	fmt.Println()
	switch {
	case best == -1:
		fmt.Printf("❌ Ninguna etapa cumplió p95 ≤ %s y errores ≤ %.1f%%: revisa la primera etapa (login, rutas, trusted_proxies).\n", *maxP95, *maxErrors*100)
	case best == len(results)-1:
		fmt.Printf("✅ Aguantó todas las etapas: %d usuarios simultáneos con p95 %s. Agrega etapas más altas para encontrar el límite.\n", results[best].VUs, ms(results[best].P95))
	default:
		fmt.Printf("📈 Capacidad: %d usuarios simultáneos (p95 %s). Con %d se pasó de los umbrales.\n", results[best].VUs, ms(results[best].P95), results[best+1].VUs)
	}

	file := *output
	if file == "" {
		file = filepath.Join("reports", "carga_"+time.Now().Format("20060102_150405")+".json")
	}
	os.MkdirAll(filepath.Dir(file), 0o755)
	data, _ := json.MarshalIndent(map[string]any{"target": target, "paths": *paths, "stages": results, "capacity_vus": capacityVUs(results, best)}, "", "  ")
	if err := os.WriteFile(file, data, 0o644); err != nil {
		fmt.Println("⚠️  No se pudo guardar el informe:", err)
	} else {
		fmt.Println("💾 Informe:", file)
	}
	return 0
}

func ms(d time.Duration) string { return fmt.Sprintf("%.0fms", float64(d.Microseconds())/1000) }

func statusLine(r load.StageResult) string {
	var parts []string
	for code, n := range r.Status {
		parts = append(parts, fmt.Sprintf("%s×%d", code, n))
	}
	if r.LoginFails > 0 {
		parts = append(parts, fmt.Sprintf("login fallido×%d", r.LoginFails))
	}
	return strings.Join(parts, " ")
}

func capacityVUs(results []load.StageResult, best int) int {
	if best < 0 {
		return 0
	}
	return results[best].VUs
}
