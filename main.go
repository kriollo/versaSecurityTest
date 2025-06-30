package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/versaSecurityTest/internal/config"
	"github.com/versaSecurityTest/internal/scanner"
	"github.com/versaSecurityTest/internal/report"
	"github.com/versaSecurityTest/internal/cli"
	tuiPackage "github.com/versaSecurityTest/internal/tui"
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
		interactive  = flag.Bool("interactive", false, "Ejecutar en modo interactivo (legacy)")
		tui          = flag.Bool("tui", false, "Ejecutar en modo TUI moderno")
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
	
	if *interactive || (len(os.Args) == 1) {
		// Ejecutar CLI interactiva legacy
		runInteractiveCLI()
		return
	}

	// Validar URL requerida para modo tradicional
	if *targetURL == "" {
		fmt.Println("❌ Error: URL objetivo es requerida")
		fmt.Println("")
		fmt.Println("📖 Opciones de uso:")
		fmt.Println("   • Modo interactivo: go run main.go -interactive")
		fmt.Println("   • Modo directo:     go run main.go -url https://ejemplo.com")
		fmt.Println("")
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
📅 Version 1.1.0 - Now with Interactive CLI!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`
	fmt.Println(banner)
}

// Funciones para CLI interactiva
func runInteractiveCLI() {
	// Banner del programa
	printInteractiveBanner()
	
	// Configuración interactiva
	interactiveConfig := &cli.InteractiveConfig{}
	
	// Configurar URL objetivo
	interactiveConfig.URL = promptURL()
	
	// Seleccionar tests a ejecutar
	interactiveConfig.SelectedTests = promptTestSelection()
	
	// Configurar formato de reporte
	interactiveConfig.ReportFormat = promptReportFormat()
	
	// Configurar archivo de salida
	interactiveConfig.OutputFile = promptOutputFile()
	
	// Configuraciones adicionales
	interactiveConfig.Verbose = promptVerbose()
	interactiveConfig.Concurrent = promptConcurrent()
	interactiveConfig.Timeout = promptTimeout()
	
	// Mostrar resumen de configuración
	showConfigSummary(interactiveConfig)
	
	// Confirmar ejecución
	if !promptConfirmation("¿Desea proceder con el escaneo?") {
		fmt.Println("❌ Escaneo cancelado por el usuario.")
		os.Exit(0)
	}
	
	// Ejecutar escaneo
	executeInteractiveScan(interactiveConfig)
}

func printInteractiveBanner() {
	banner := `
██╗   ██╗███████╗██████╗ ███████╗ █████╗ ███████╗███████╗ ██████╗
██║   ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║   ██║█████╗  ██████╔╝███████╗███████║███████╗█████╗  ██║     
╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══██║╚════██║██╔══╝  ██║     
 ╚████╔╝ ███████╗██║  ██║███████║██║  ██║███████║███████╗╚██████╗
  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝

🔐 VersaSecurityTest - Interactive Web Security Scanner
📅 Version 1.1.0 - Now with Interactive CLI!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

¡Bienvenido al modo interactivo! 🚀
Configuraremos su escaneo paso a paso para obtener los mejores resultados.
`
	fmt.Println(banner)
}

func promptURL() string {
	reader := bufio.NewReader(os.Stdin)
	
	for {
		fmt.Print("\n🎯 Ingrese la URL objetivo: ")
		url, _ := reader.ReadString('\n')
		url = strings.TrimSpace(url)
		
		if url == "" {
			fmt.Println("❌ La URL no puede estar vacía.")
			continue
		}
		
		// Validación básica de URL
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			fmt.Printf("⚠️  La URL no tiene protocolo. ¿Desea usar HTTPS? (https://%s) [Y/n]: ", url)
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))
			
			if response == "" || response == "y" || response == "yes" {
				url = "https://" + url
			} else {
				url = "http://" + url
			}
		}
		
		fmt.Printf("✅ URL configurada: %s\n", url)
		return url
	}
}

func promptTestSelection() []string {
	fmt.Println("\n📋 SELECCIÓN DE TESTS DE SEGURIDAD")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	
	// Lista de tests disponibles
	availableTests := []cli.TestOption{
		{ID: "basic", Name: "Conectividad Básica", Description: "Pruebas fundamentales de conectividad y configuración", Enabled: true},
		{ID: "sql", Name: "SQL Injection", Description: "Detecta vulnerabilidades de inyección SQL", Enabled: true},
		{ID: "xss", Name: "Cross-Site Scripting (XSS)", Description: "Identifica posibles vectores de ataque XSS", Enabled: true},
		{ID: "headers", Name: "Headers de Seguridad", Description: "Verifica headers HTTP de seguridad", Enabled: true},
		{ID: "ssl", Name: "SSL/TLS Security", Description: "Analiza configuración de certificados SSL", Enabled: false},
		{ID: "csrf", Name: "CSRF Protection", Description: "Verifica protección contra CSRF", Enabled: false},
		{ID: "bruteforce", Name: "Brute Force", Description: "Detecta vulnerabilidades de fuerza bruta", Enabled: false},
		{ID: "fileupload", Name: "File Upload", Description: "Analiza seguridad en carga de archivos", Enabled: false},
		{ID: "dirtraversal", Name: "Directory Traversal", Description: "Detecta vulnerabilidades de path traversal", Enabled: false},
		{ID: "info", Name: "Information Disclosure", Description: "Detecta exposición de información sensible", Enabled: true},
	}
	
	reader := bufio.NewReader(os.Stdin)
	
	// Mostrar tests disponibles
	fmt.Println("Seleccione los tests que desea ejecutar:")
	for i, test := range availableTests {
		status := "❌"
		if test.Enabled {
			status = "✅"
		}
		fmt.Printf("%s [%d] %s\n", status, i+1, test.Name)
		fmt.Printf("    📝 %s\n", test.Description)
		fmt.Println()
	}
	
	fmt.Println("Opciones:")
	fmt.Println("  • Números separados por comas (ej: 1,2,3)")
	fmt.Println("  • 'all' para seleccionar todos")
	fmt.Println("  • 'recommended' para seleccionar los recomendados (marcados con ✅)")
	fmt.Println("  • 'Enter' para usar la selección recomendada")
	
	for {
		fmt.Print("\n🔍 Su selección: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		
		// Valor por defecto: tests recomendados
		if input == "" {
			input = "recommended"
		}
		
		selectedTests := []string{}
		
		switch strings.ToLower(input) {
		case "all":
			for _, test := range availableTests {
				selectedTests = append(selectedTests, test.ID)
			}
		case "recommended":
			for _, test := range availableTests {
				if test.Enabled {
					selectedTests = append(selectedTests, test.ID)
				}
			}
		default:
			// Parsear números
			parts := strings.Split(input, ",")
			valid := true
			
			for _, part := range parts {
				num, err := strconv.Atoi(strings.TrimSpace(part))
				if err != nil || num < 1 || num > len(availableTests) {
					fmt.Printf("❌ Número inválido: %s\n", part)
					valid = false
					break
				}
				selectedTests = append(selectedTests, availableTests[num-1].ID)
			}
			
			if !valid {
				continue
			}
		}
		
		// Mostrar selección
		fmt.Printf("\n✅ Tests seleccionados (%d):\n", len(selectedTests))
		for _, testID := range selectedTests {
			for _, test := range availableTests {
				if test.ID == testID {
					fmt.Printf("   • %s\n", test.Name)
					break
				}
			}
		}
		
		return selectedTests
	}
}

func promptReportFormat() string {
	fmt.Println("\n📊 FORMATO DE REPORTE")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	
	formats := []cli.FormatOption{
		{ID: "json", Name: "JSON", Description: "Formato estructurado, ideal para integración con otras herramientas"},
		{ID: "table", Name: "Tabla ASCII", Description: "Visualización clara y organizada directamente en terminal"},
		{ID: "html", Name: "HTML", Description: "Reporte profesional con diseño responsivo y gráficos"},
	}
	
	for i, format := range formats {
		fmt.Printf("[%d] %s\n", i+1, format.Name)
		fmt.Printf("    📝 %s\n", format.Description)
		fmt.Println()
	}
	
	reader := bufio.NewReader(os.Stdin)
	
	for {
		fmt.Print("🎨 Seleccione el formato [1-3] (por defecto: JSON): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		
		if input == "" {
			input = "1"
		}
		
		choice, err := strconv.Atoi(input)
		if err != nil || choice < 1 || choice > len(formats) {
			fmt.Println("❌ Opción inválida. Por favor seleccione 1, 2 o 3.")
			continue
		}
		
		selectedFormat := formats[choice-1]
		fmt.Printf("✅ Formato seleccionado: %s\n", selectedFormat.Name)
		return selectedFormat.ID
	}
}

func promptOutputFile() string {
	reader := bufio.NewReader(os.Stdin)
	
	fmt.Print("\n📁 Archivo de salida (opcional, Enter para mostrar en pantalla): ")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)
	
	if filename != "" {
		fmt.Printf("✅ Archivo de salida: %s\n", filename)
	} else {
		fmt.Println("✅ Salida: Pantalla (stdout)")
	}
	
	return filename
}

func promptVerbose() bool {
	return promptYesNo("🔍 ¿Activar modo verbose (mostrar detalles durante el escaneo)?", false)
}

func promptConcurrent() int {
	reader := bufio.NewReader(os.Stdin)
	
	for {
		fmt.Print("\n⚙️  Número de hilos concurrentes [1-20] (por defecto: 10): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		
		if input == "" {
			return 10
		}
		
		concurrent, err := strconv.Atoi(input)
		if err != nil || concurrent < 1 || concurrent > 20 {
			fmt.Println("❌ Valor inválido. Por favor ingrese un número entre 1 y 20.")
			continue
		}
		
		fmt.Printf("✅ Hilos concurrentes: %d\n", concurrent)
		return concurrent
	}
}

func promptTimeout() time.Duration {
	reader := bufio.NewReader(os.Stdin)
	
	for {
		fmt.Print("\n⏱️  Timeout por request en segundos [5-120] (por defecto: 30): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		
		if input == "" {
			return 30 * time.Second
		}
		
		seconds, err := strconv.Atoi(input)
		if err != nil || seconds < 5 || seconds > 120 {
			fmt.Println("❌ Valor inválido. Por favor ingrese un número entre 5 y 120.")
			continue
		}
		
		timeout := time.Duration(seconds) * time.Second
		fmt.Printf("✅ Timeout: %v\n", timeout)
		return timeout
	}
}

func promptYesNo(question string, defaultValue bool) bool {
	reader := bufio.NewReader(os.Stdin)
	
	defaultStr := "n"
	if defaultValue {
		defaultStr = "y"
	}
	
	fmt.Printf("%s [y/n] (por defecto: %s): ", question, defaultStr)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	
	if input == "" {
		return defaultValue
	}
	
	return input == "y" || input == "yes"
}

func promptConfirmation(question string) bool {
	return promptYesNo(question, true)
}

func showConfigSummary(config *cli.InteractiveConfig) {
	fmt.Println("\n📋 RESUMEN DE CONFIGURACIÓN")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("🎯 URL Objetivo:      %s\n", config.URL)
	fmt.Printf("🔍 Tests:             %d seleccionados\n", len(config.SelectedTests))
	fmt.Printf("📊 Formato Reporte:   %s\n", strings.ToUpper(config.ReportFormat))
	
	if config.OutputFile != "" {
		fmt.Printf("📁 Archivo Salida:    %s\n", config.OutputFile)
	} else {
		fmt.Printf("📁 Archivo Salida:    Pantalla (stdout)\n")
	}
	
	fmt.Printf("🔍 Modo Verbose:      %t\n", config.Verbose)
	fmt.Printf("⚙️  Hilos:            %d\n", config.Concurrent)
	fmt.Printf("⏱️  Timeout:          %v\n", config.Timeout)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func executeInteractiveScan(interactiveConfig *cli.InteractiveConfig) {
	// Crear configuración del scanner
	cfg := &config.Config{
		Concurrent: interactiveConfig.Concurrent,
		Timeout:    interactiveConfig.Timeout,
		Verbose:    interactiveConfig.Verbose,
		Tests: config.TestConfig{
			SQLInjection:    contains(interactiveConfig.SelectedTests, "sql"),
			XSS:            contains(interactiveConfig.SelectedTests, "xss"),
			HTTPHeaders:    contains(interactiveConfig.SelectedTests, "headers"),
			SSLAnalysis:    contains(interactiveConfig.SelectedTests, "ssl"),
			CSRFProtection: contains(interactiveConfig.SelectedTests, "csrf"),
			BruteForce:     contains(interactiveConfig.SelectedTests, "bruteforce"),
			FileUpload:     contains(interactiveConfig.SelectedTests, "fileupload"),
			DirTraversal:   contains(interactiveConfig.SelectedTests, "dirtraversal"),
			InfoDisclosure: contains(interactiveConfig.SelectedTests, "info"),
		},
	}
	
	// Inicializar el escáner
	webScanner := scanner.NewWebScanner(cfg)
	
	fmt.Printf("\n🚀 INICIANDO ESCANEO DE SEGURIDAD\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("🎯 Objetivo: %s\n", interactiveConfig.URL)
	fmt.Printf("⚙️  Configuración: %d hilos, timeout %v\n", cfg.Concurrent, cfg.Timeout)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	
	// Ejecutar escaneo
	startTime := time.Now()
	scanResult := webScanner.ScanURL(interactiveConfig.URL)
	duration := time.Since(startTime)
	
	// Completar información del reporte
	scanResult.URL = interactiveConfig.URL
	scanResult.ScanDate = time.Now()
	scanResult.Duration = duration
	
	// Generar reporte
	var output string
	switch interactiveConfig.ReportFormat {
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
	if interactiveConfig.OutputFile != "" {
		err := os.WriteFile(interactiveConfig.OutputFile, []byte(output), 0644)
		if err != nil {
			log.Fatalf("Error escribiendo archivo: %v", err)
		}
		fmt.Printf("\n📄 Reporte guardado en: %s\n", interactiveConfig.OutputFile)
		
		// Mostrar resumen en pantalla también
		fmt.Println("\n📊 RESUMEN DE RESULTADOS")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		showScanSummary(scanResult)
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

func showScanSummary(result *scanner.ScanResult) {
	fmt.Printf("📊 Tests ejecutados: %d\n", result.TestsExecuted)
	fmt.Printf("✅ Tests pasaron: %d\n", result.TestsPassed)
	fmt.Printf("❌ Tests fallaron: %d\n", result.TestsFailed)
	fmt.Printf("⚠️  Puntuación de seguridad: %.1f/10 (%s)\n", 
		result.SecurityScore.Value, result.SecurityScore.Risk)
	
	if len(result.Recommendations) > 0 {
		fmt.Println("\n💡 Recomendaciones principales:")
		for i, rec := range result.Recommendations {
			if i >= 3 { // Mostrar solo las primeras 3
				fmt.Printf("   ... y %d más (ver reporte completo)\n", len(result.Recommendations)-3)
				break
			}
			fmt.Printf("   • %s\n", rec)
		}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
