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
	"github.com/versaSecurityTest/internal/update"
)

func main() {
	// Prueba de capacidad: subcomando con sus propias opciones
	if len(os.Args) > 1 && os.Args[1] == "load" {
		os.Exit(runLoad(os.Args[2:]))
	}
	// Prueba de resiliencia ante DoS
	if len(os.Args) > 1 && os.Args[1] == "flood" {
		os.Exit(runFlood(os.Args[2:]))
	}

	// Configuración de flags
	var (
		targetURL  = flag.String("url", "", "URL objetivo para escanear (modo CLI)")
		outputFile = flag.String("output", "", "Archivo de salida para el reporte (opcional)")
		configFile = flag.String("config", "config.json", "Archivo de configuración")
		verbose    = flag.Bool("verbose", false, "Modo verbose para debugging")
		format     = flag.String("format", "json", "Formato de salida (json, table, html)")
		concurrent = flag.Int("concurrent", 10, "Número de requests concurrentes")
		timeout    = flag.Duration("timeout", 30*time.Second, "Timeout por request")
		cli        = flag.Bool("cli", false, "Forzar modo CLI (por defecto usa TUI)")
		updateFlag = flag.Bool("update", false, "Buscar actualizaciones de la aplicación")
	)
	flag.Parse()

	// Procesar comando de actualización
	if *updateFlag {
		fmt.Println("🚀 Iniciando verificador de actualizaciones...")
		if err := update.CheckForUpdates("2.1.2"); err != nil {
			fmt.Printf("❌ Error al buscar actualizaciones: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Determinar modo de ejecución
	// Si se especifica URL o se fuerza CLI, usar modo CLI
	// De lo contrario, usar TUI como predeterminado
	if *targetURL != "" || *cli {
		// Modo CLI
		if *targetURL == "" {
			fmt.Println("❌ Error: URL objetivo es requerida para modo CLI")
			fmt.Println("")
			fmt.Println("📖 Opciones de uso:")
			fmt.Println("   • Modo TUI (predeterminado): ./versaSecurityTest.exe")
			fmt.Println("   • Modo CLI:                  ./versaSecurityTest.exe -url https://ejemplo.com")
			fmt.Println("   • Forzar CLI:                ./versaSecurityTest.exe -cli")
			fmt.Println("   • Actualización:             ./versaSecurityTest.exe -update")
			fmt.Println("   • Prueba de capacidad:       ./versaSecurityTest.exe load -url https://ejemplo.com -help")
			fmt.Println("   • Resiliencia ante DoS:      ./versaSecurityTest.exe flood -url https://ejemplo.com -help")
			fmt.Println("")
			flag.PrintDefaults()
			os.Exit(1)
		}
		// Continuar con modo CLI...
	} else {
		// Modo TUI predeterminado
		if err := tuiPackage.RunTUI(); err != nil {
			log.Fatalf("Error ejecutando TUI: %v", err)
		}
		return
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
  🛡️  VERSA SECURITY
  ──────────────────
  Automated Web Security Scanner
  v2.1.2 | Standard & Professional Mode
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`
	fmt.Println(tuiPackage.HeaderStyle.Render(banner))
}
