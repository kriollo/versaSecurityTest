package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/versaSecurityTest/internal/config"
	"github.com/versaSecurityTest/internal/report"
	"github.com/versaSecurityTest/internal/scanner"
	tuiPackage "github.com/versaSecurityTest/internal/tui"
)

func main() {
	// Configuración de flags
	var (
		targetURL  = flag.String("url", "", "URL objetivo para escanear (requerido)")
		outputFile = flag.String("output", "", "Archivo de salida para el reporte (opcional)")
		configFile = flag.String("config", "config.json", "Archivo de configuración")
		verbose    = flag.Bool("verbose", false, "Modo verbose para debugging")
		format     = flag.String("format", "json", "Formato de salida (json, table, html)")
		concurrent = flag.Int("concurrent", 10, "Número de requests concurrentes")
		timeout    = flag.Duration("timeout", 30*time.Second, "Timeout por request")
		tui        = flag.Bool("tui", false, "Ejecutar en modo TUI moderno")
	)
	flag.Parse()

	// Verificar modos de ejecución
	if *tui {
		// Ejecutar TUI moderna
		if err := tuiPackage.RunTUI(); err != nil {
			log.Fatalf("Error ejecutando TUI: %v", err)
		}
		return
	}

	// Validar URL requerida para modo CLI
	if *targetURL == "" {
		fmt.Println("❌ Error: URL objetivo es requerida")
		fmt.Println("")
		fmt.Println("📖 Opciones de uso:")
		fmt.Println("   • Modo TUI:     go run main.go -tui")
		fmt.Println("   • Modo CLI:     go run main.go -url https://ejemplo.com")
		fmt.Println("")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Banner del programa
	printBanner()

	fmt.Printf("🎯 Iniciando escaneo de seguridad para: %s\n", *targetURL)

	// Cargar configuración desde archivo para timeout y otras configuraciones
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		fmt.Printf("⚠️  Error cargando configuración: %v, usando valores por defecto\n", err)
		cfg = config.DefaultConfig()
	}

	// Usar valores de configuración con posibilidad de override desde CLI
	actualConcurrent := *concurrent
	if actualConcurrent == 10 { // Valor por defecto del flag
		actualConcurrent = cfg.Concurrent
	}

	actualTimeout := *timeout
	if actualTimeout == 30*time.Second { // Valor por defecto del flag
		actualTimeout = time.Duration(cfg.Timeout)
	}

	fmt.Printf("⚙️  Configuración: %d hilos, timeout %v\n", actualConcurrent, actualTimeout)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Ejecutar escaneo usando funciones unificadas
	scanOptions := scanner.ScanOptions{
		TargetURL:        *targetURL,
		ConfigFile:       *configFile,
		Verbose:          *verbose,
		Concurrent:       actualConcurrent,
		Timeout:          actualTimeout,
		UseAdvancedTests: cfg.Tests.UseAdvancedTests, // Usar configuración de config.json
		EnabledTests:     nil,                        // Usar configuración del archivo config.json
		SkipChannel:      nil,                        // CLI usa canal interno
	}

	startTime := time.Now()
	scanResult, err := scanner.ExecuteScan(scanOptions)
	if err != nil {
		log.Fatalf("Error ejecutando escaneo: %v", err)
	}
	duration := time.Since(startTime)
	scanResult.Duration = duration

	// Configurar opciones de reporte
	reportOptions := report.ReportOptions{
		Format:        *format,
		OutputFile:    *outputFile,
		UseReportsDir: true, // Siempre usar directorio reports/
	}

	// Mostrar o guardar resultado
	if *outputFile != "" {
		// Guardar en archivo específico
		savedFile, err := report.SaveReport(scanResult, reportOptions)
		if err != nil {
			log.Fatalf("Error guardando reporte: %v", err)
		}
		fmt.Printf("\n📄 Reporte guardado en: %s\n", savedFile)
	} else {
		// Mostrar en consola
		output, err := report.GenerateReport(scanResult, *format)
		if err != nil {
			log.Fatalf("Error generando reporte: %v", err)
		}
		fmt.Println("\n" + output)
	}

	// Auto-guardar si está configurado y no se especificó archivo de salida
	if (cfg != nil && cfg.AutoSave) && *outputFile == "" {
		autoFilename, err := report.AutoSaveReport(scanResult)
		if err != nil {
			log.Printf("Advertencia: No se pudo auto-guardar el reporte: %v", err)
		} else {
			fmt.Printf("💾 Auto-guardado habilitado: Reporte guardado en %s\n", autoFilename)
		}
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
📅 Version 1.1.0 - CLI & TUI Modes Available
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`
	fmt.Println(banner)
}
