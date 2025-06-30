package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/versaSecurityTest/internal/config"
	"github.com/versaSecurityTest/internal/scanner"
	"github.com/versaSecurityTest/internal/report"
)

func main() {
	// Configuración de flags
	var (
		targetURL    = flag.String("url", "", "URL objetivo para escanear (requerido)")
		outputFile   = flag.String("output", "", "Archivo de salida para el reporte (opcional)")
		configFile   = flag.String("config", "config.json", "Archivo de configuración")
		verbose      = flag.Bool("verbose", false, "Modo verbose para debugging")
		format       = flag.String("format", "json", "Formato de salida (json, table, html)")
		concurrent   = flag.Int("concurrent", 10, "Número de requests concurrentes")
		timeout      = flag.Duration("timeout", 30*time.Second, "Timeout por request")
	)
	flag.Parse()

	// Validar URL requerida
	if *targetURL == "" {
		fmt.Println("Error: URL objetivo es requerida")
		fmt.Println("Uso: go run main.go -url https://ejemplo.com")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Banner del programa
	printBanner()

	// Cargar configuración
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Printf("Advertencia: No se pudo cargar config, usando valores por defecto: %v", err)
		cfg = config.DefaultConfig()
	}

	// Sobrescribir configuración con flags
	cfg.Concurrent = *concurrent
	cfg.Timeout = *timeout
	cfg.Verbose = *verbose

	// Inicializar el escáner
	webScanner := scanner.NewWebScanner(cfg)

	fmt.Printf("🎯 Iniciando escaneo de seguridad para: %s\n", *targetURL)
	fmt.Printf("⚙️  Configuración: %d hilos, timeout %v\n", cfg.Concurrent, cfg.Timeout)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Ejecutar escaneo
	startTime := time.Now()
	scanResult := webScanner.ScanURL(*targetURL)
	duration := time.Since(startTime)

	// Completar información del reporte
	scanResult.URL = *targetURL
	scanResult.ScanDate = time.Now()
	scanResult.Duration = duration

	// Generar reporte
	var output string
	switch *format {
	case "table":
		output = report.GenerateTableReport(scanResult)
	case "html":
		output = report.GenerateHTMLReport(scanResult)
	default:
		jsonBytes, err := json.MarshalIndent(scanResult, "", "  ")
		if err != nil {
			log.Fatalf("Error generando reporte JSON: %v", err)
		}
		output = string(jsonBytes)
	}

	// Mostrar o guardar resultado
	if *outputFile != "" {
		err := os.WriteFile(*outputFile, []byte(output), 0644)
		if err != nil {
			log.Fatalf("Error escribiendo archivo: %v", err)
		}
		fmt.Printf("\n📄 Reporte guardado en: %s\n", *outputFile)
	} else {
		fmt.Println("\n" + output)
	}

	// Resumen final
	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("✅ Escaneo completado en %v\n", duration.Round(time.Millisecond))
	fmt.Printf("📊 Tests ejecutados: %d | Pasaron: %d | Fallaron: %d\n", 
		scanResult.TestsExecuted, scanResult.TestsPassed, scanResult.TestsFailed)
	fmt.Printf("⚠️  Nota de seguridad: %.1f/10 (%s)\n", 
		scanResult.SecurityScore.Value, scanResult.SecurityScore.Risk)
}

func printBanner() {
	banner := `
██╗   ██╗███████╗██████╗ ███████╗ █████╗ ███████╗███████╗ ██████╗
██║   ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║   ██║█████╗  ██████╔╝███████╗███████║███████╗█████╗  ██║     
╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══██║╚════██║██╔══╝  ██║     
 ╚████╔╝ ███████╗██║  ██║███████║██║  ██║███████║███████╗╚██████╗
  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝

🔐 VersaSecurityTest - Automated Web Security Scanner
📅 Version 1.0.0 - Desarrollado para análisis de seguridad web
`
	fmt.Println(banner)
}
