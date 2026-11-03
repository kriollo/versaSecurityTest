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

// runFlood es `versaSecurity flood -url ...`: prueba de resiliencia ante denegación de servicio.
// Lanza un flujo intenso desde muchas IP y reporta si el límite de peticiones lo contiene o si la app
// se degrada. Solo contra servidores propios o con autorización expresa.
func runFlood(args []string) int {
	fs := flag.NewFlagSet("flood", flag.ExitOnError)
	urlFlag := fs.String("url", "", "URL base del objetivo (obligatoria)")
	path := fs.String("path", "/", "Ruta a golpear")
	workers := fs.Int("workers", 100, "Peticiones en paralelo")
	duration := fs.Duration("duration", 20*time.Second, "Duración del flujo")
	rotateIP := fs.Bool("rotate-ip", true, "Una IP distinta por petición en X-Forwarded-For (prueba el límite por IP)")
	timeout := fs.Duration("timeout", 10*time.Second, "Timeout por petición")
	insecure := fs.Bool("insecure", false, "No verificar el certificado TLS")
	output := fs.String("output", "", "Archivo JSON del informe (por defecto reports/flood_<fecha>.json)")
	yes := fs.Bool("yes", false, "Confirmar que el objetivo es propio o autorizado")
	fs.Parse(args)

	target := *urlFlag
	if target == "" {
		fmt.Println("❌ Falta -url. Uso: versaSecurity flood -url http://localhost:8000 -path /admin/login -workers 200 -duration 30s")
		fs.PrintDefaults()
		return 1
	}
	if !*yes && !strings.Contains(target, "localhost") && !strings.Contains(target, "127.0.0.1") {
		fmt.Printf("⚠️  Vas a enviar un flujo intenso a %s.\n", target)
		fmt.Println("   Esto solo es legal contra un servidor propio o con autorización expresa. Añade -yes para continuar.")
		return 1
	}

	fmt.Printf("💥 Prueba de resiliencia (DoS) contra %s%s: %d en paralelo, %s", target, *path, *workers, *duration)
	if *rotateIP {
		fmt.Print(", IP rotada por petición")
	}
	fmt.Println()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := load.RunFlood(ctx, load.FloodOptions{
		BaseURL: target, Path: *path, Workers: *workers, Duration: *duration,
		RotateIP: *rotateIP, Timeout: *timeout, Insecure: *insecure,
	}, func(done int, rps float64) {
		fmt.Printf("\r  %d peticiones (%.0f req/s)   ", done, rps)
	})
	if err != nil {
		fmt.Println("\n❌", err)
		return 1
	}

	fmt.Printf("\r%60s\r", "")
	fmt.Printf("Peticiones: %d (%.0f req/s)  p50 %s  p95 %s  p99 %s  máx %s\n",
		res.Requests, res.RPS, ms(res.P50), ms(res.P95), ms(res.P99), ms(res.Max))
	fmt.Printf("  2xx/3xx: %d  |  429 (frenadas): %d  |  5xx: %d  |  errores de red: %d\n",
		res.OK, res.RateLimited, res.ServerError, res.NetworkErr)
	fmt.Println(res.Verdict())

	file := *output
	if file == "" {
		file = filepath.Join("reports", "flood_"+time.Now().Format("20060102_150405")+".json")
	}
	os.MkdirAll(filepath.Dir(file), 0o755)
	data, _ := json.MarshalIndent(map[string]any{"target": target, "path": *path, "workers": *workers, "result": res, "verdict": res.Verdict()}, "", "  ")
	if err := os.WriteFile(file, data, 0o644); err == nil {
		fmt.Println("💾 Informe:", file)
	}
	return 0
}
