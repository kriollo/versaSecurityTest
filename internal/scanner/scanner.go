package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/versaSecurityTest/internal/config"
	"github.com/versaSecurityTest/internal/scanner/tests"
)

// TestRunner define la interfaz que deben implementar todos los tests
type TestRunner interface {
	Run(targetURL string, client tests.HTTPClient, payloads *config.PayloadConfig) tests.TestResult
}

// WebScanner es el escáner principal
type WebScanner struct {
	config   *config.Config
	payloads *config.PayloadConfig
	client   tests.HTTPClient
}

// ScanResult contiene los resultados del escaneo
type ScanResult struct {
	URL             string             `json:"url"`
	ScanDate        time.Time          `json:"scan_date"`
	Duration        time.Duration      `json:"duration"`
	TestsExecuted   int                `json:"tests_executed"`
	TestsPassed     int                `json:"tests_passed"`
	TestsFailed     int                `json:"tests_failed"`
	TestsSkipped    int                `json:"tests_skipped"`
	TestsTimeout    int                `json:"tests_timeout"`
	SecurityScore   SecurityScore      `json:"security_score"`
	TestResults     []tests.TestResult `json:"test_results"`
	Recommendations []string           `json:"recommendations"`
}

// SecurityScore representa la puntuación de seguridad
type SecurityScore struct {
	Value float64 `json:"value"`
	Risk  string  `json:"risk"`
}

// NewWebScanner crea una nueva instancia del escáner
func NewWebScanner(cfg *config.Config) *WebScanner {
	return &WebScanner{
		config:   cfg,
		payloads: config.GetPayloads(),
		client:   tests.NewBasicHTTPClient(),
	}
}

// ScanURL ejecuta todos los tests de seguridad en la URL objetivo
func (ws *WebScanner) ScanURL(targetURL string) *ScanResult {
	return ws.ScanURLWithOptions(targetURL, nil)
}

// ScanURLWithOptions ejecuta el escaneo con opciones adicionales como canal de skip
func (ws *WebScanner) ScanURLWithOptions(targetURL string, skipChannel chan bool) *ScanResult {
	// Validar URL
	_, err := url.Parse(targetURL)
	if err != nil {
		return &ScanResult{
			TestResults: []tests.TestResult{
				{
					TestName:    "URL Validation",
					Status:      "Failed",
					Description: fmt.Sprintf("URL inválida: %v", err),
					Severity:    "High",
				},
			},
		}
	}

	result := &ScanResult{
		URL:             targetURL,
		ScanDate:        time.Now(),
		TestResults:     []tests.TestResult{},
		Recommendations: []string{},
	}

	// Variables para progreso
	startTime := time.Now()
	completedTests := 0
	var progressMutex sync.Mutex

	// Función para mostrar progreso con instrucciones
	showProgress := func(testName string, completed, total int) {
		progressMutex.Lock()
		defer progressMutex.Unlock()

		elapsed := time.Since(startTime)
		percent := float64(completed) / float64(total) * 100
		fmt.Printf("\r🔍 [%s] Test: %s | Progreso: %.1f%% [%d/%d] | Tiempo: %v | 'S'+Enter=Saltar",
			time.Now().Format("15:04:05"), testName, percent, completed, total, elapsed.Round(time.Second))
	}

	// Configurar canal de skip
	var skipChan chan bool
	if skipChannel != nil {
		// Usar canal externo (TUI mode)
		skipChan = skipChannel
	} else {
		// Crear canal interno y lanzar goroutine para input de CLI
		skipChan = make(chan bool, 1)
		var inputMutex sync.Mutex

		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			for {
				if scanner.Scan() {
					inputMutex.Lock()
					input := strings.ToLower(strings.TrimSpace(scanner.Text()))
					inputMutex.Unlock()

					if input == "s" || input == "skip" {
						fmt.Printf("\n🚨 Comando de salto detectado - cancelando test actual...\n")
						select {
						case skipChan <- true:
							fmt.Printf("✅ Test será saltado\n")
						default:
							// Canal lleno, test ya está siendo cancelado
							fmt.Printf("⚠️  Test ya está siendo cancelado\n")
						}
					}
				}
			}
		}()
	}

	// Ejecutar tests habilitados
	testRunners := ws.getEnabledTests()
	result.TestsExecuted = len(testRunners)

	// Mostrar instrucciones iniciales
	fmt.Printf("\n💡 INSTRUCCIONES PARA SALTAR TESTS:\n")
	fmt.Printf("   • Escribe 'S' (o 'skip') y presiona Enter para saltar el test actual\n")
	fmt.Printf("   • El comando será procesado inmediatamente\n")
	fmt.Printf("   • Tests saltados se marcan como 'Skipped' en el reporte\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// Mostrar progreso inicial
	showProgress("Iniciando escaneo...", 0, len(testRunners))

	// Ejecutar tests uno por uno (secuencial para permitir cancelación)
	for i, testRunner := range testRunners {
		// Timeout por test individual (máximo 2 minutos por test)
		testTimeout := 2 * time.Minute
		testCtx, cancel := context.WithTimeout(context.Background(), testTimeout)

		testResult := make(chan tests.TestResult, 1)
		testStartTime := time.Now()

		// Ejecutar test en goroutine
		go func(tr TestRunner) {
			result := tr.Run(targetURL, ws.client, ws.payloads)
			select {
			case testResult <- result:
			case <-testCtx.Done():
				// Test cancelado o timeout
			}
		}(testRunner)

		// Obtener nombre del test para mostrar progreso
		testName := getTestName(testRunner)

		// Esperar resultado del test, cancelación o timeout
		var finalResult tests.TestResult
		testCompleted := false

		for !testCompleted {
			select {
			case res := <-testResult:
				// Test completado exitosamente
				finalResult = res
				testCompleted = true

			case <-skipChan:
				// Usuario solicitó saltar
				cancel()
				finalResult = tests.TestResult{
					TestName:    fmt.Sprintf("%s (Saltado)", testName),
					Status:      "Skipped",
					Description: fmt.Sprintf("Test saltado por usuario después de %v", time.Since(testStartTime).Round(time.Second)),
					Severity:    "Info",
					Details:     []string{"Usuario solicitó saltar al siguiente test"},
				}
				testCompleted = true
				fmt.Printf("\n⏭️  Test '%s' saltado exitosamente - continuando...\n", testName)

			case <-testCtx.Done():
				// Timeout del test
				cancel()
				finalResult = tests.TestResult{
					TestName:    fmt.Sprintf("%s (Timeout)", testName),
					Status:      "Timeout",
					Description: fmt.Sprintf("Test cancelado por timeout después de %v", testTimeout),
					Severity:    "Warning",
					Details:     []string{"Test excedió el tiempo límite de 2 minutos"},
				}
				testCompleted = true
				fmt.Printf("\n⏰ Test cancelado por timeout\n")

			default:
				// Actualizar progreso mientras el test se ejecuta
				showProgress(testName, i, len(testRunners))
				time.Sleep(100 * time.Millisecond)
			}
		}

		// Limpiar context
		cancel()

		// Procesar resultado
		result.TestResults = append(result.TestResults, finalResult)

		// Actualizar contadores según el resultado
		switch finalResult.Status {
		case "Passed":
			result.TestsPassed++
		case "Skipped":
			result.TestsSkipped++
		case "Timeout":
			result.TestsTimeout++
		default:
			result.TestsFailed++
		}

		// Actualizar progreso final del test
		completedTests++
		showProgress(finalResult.TestName, completedTests, len(testRunners))

		if ws.config.Verbose {
			status := "✅"
			if finalResult.Status != "Passed" {
				if finalResult.Status == "Skipped" {
					status = "⏭️"
				} else if finalResult.Status == "Timeout" {
					status = "⏰"
				} else {
					status = "❌"
				}
			}
			fmt.Printf("\n%s %s: %s", status, finalResult.TestName, finalResult.Description)
		}
	}

	// Finalizar línea de progreso
	fmt.Printf("\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// Finalizar información de duración
	result.Duration = time.Since(startTime)

	// Calcular puntuación de seguridad
	result.SecurityScore = ws.calculateSecurityScore(result)

	// Generar recomendaciones
	result.Recommendations = ws.generateRecommendations(result)

	return result
}

// getEnabledTests retorna la lista de tests habilitados
func (ws *WebScanner) getEnabledTests() []TestRunner {
	var testRunners []TestRunner

	// Test básico de conectividad (siempre se ejecuta)
	testRunners = append(testRunners, &tests.BasicTest{})

	// Categoría INFO - Recolección de información
	if ws.config.Tests.InfoGathering {
		testRunners = append(testRunners, &tests.InfoGatheringTest{})
		testRunners = append(testRunners, &tests.DirectoryEnumerationTest{})
		testRunners = append(testRunners, &tests.HTTPMethodsTest{})
	}

	// Categoría CONF - Configuración
	if ws.config.Tests.Configuration {
		testRunners = append(testRunners, &tests.ConfigurationTest{})
		testRunners = append(testRunners, &tests.DefaultPagesTest{})
		testRunners = append(testRunners, &tests.ErrorLeakageTest{})
	}

	// Categoría IDNT - Gestión de identidad
	if ws.config.Tests.IdentityMgmt {
		testRunners = append(testRunners, &tests.IdentityManagementTest{})
		testRunners = append(testRunners, &tests.UserEnumerationTest{})
	}

	// Categoría ATHZ - Autorización
	if ws.config.Tests.Authorization {
		testRunners = append(testRunners, &tests.AuthorizationTest{})
		testRunners = append(testRunners, &tests.DirectObjectReferenceTest{})
	}

	// Categoría SESS - Gestión de sesiones
	if ws.config.Tests.SessionMgmt {
		testRunners = append(testRunners, &tests.SessionMgmtTest{})
	}

	// Categoría INPV - Validación de entrada
	if ws.config.Tests.InputValidation {
		testRunners = append(testRunners, &tests.InputValidationTest{})
		testRunners = append(testRunners, &tests.DataValidationTest{})
	}

	// Tests de SQL Injection (avanzados si está habilitado)
	if ws.config.Tests.SQLInjection {
		if ws.config.Tests.UseAdvancedTests {
			// Test avanzado con 60+ payloads y técnicas de evasión
			testRunners = append(testRunners, &tests.AdvancedSQLInjectionTest{})
		} else {
			// Test básico (compatible con versiones anteriores)
			testRunners = append(testRunners, &tests.SQLInjectionTest{})
		}
	}

	// Tests de XSS (avanzados si está habilitado)
	if ws.config.Tests.XSS {
		if ws.config.Tests.UseAdvancedTests {
			// Test avanzado con múltiples técnicas de bypass
			testRunners = append(testRunners, &tests.AdvancedXSSTest{})
		} else {
			// Test básico (compatible con versiones anteriores)
			testRunners = append(testRunners, &tests.XSSTest{})
		}
	}

	// Tests de HTTP Headers (avanzados si está habilitado)
	if ws.config.Tests.HTTPHeaders {
		if ws.config.Tests.UseAdvancedTests {
			// Test avanzado con validación de configuración específica
			testRunners = append(testRunners, &tests.AdvancedSecurityHeadersTest{})
		}
		// Nota: Test básico de headers deshabilitado temporalmente hasta solucionar problemas de compilación
	}

	// Tests de Directory Traversal (avanzados si está habilitado)
	if ws.config.Tests.DirTraversal {
		if ws.config.Tests.UseAdvancedTests {
			// Test avanzado con múltiples técnicas de encoding
			testRunners = append(testRunners, &tests.AdvancedDirectoryTraversalTest{})
		}
		// Nota: Test básico de traversal deshabilitado temporalmente hasta solucionar problemas de compilación
	}

	// Categoría CRYP - Criptografía
	if ws.config.Tests.Cryptography {
		testRunners = append(testRunners, &tests.CryptographyTest{})
	}

	// Categoría BUSL - Lógica de negocio
	if ws.config.Tests.BusinessLogic {
		testRunners = append(testRunners, &tests.BusinessLogicTest{})
	}

	// Categoría CLNT - Cliente
	if ws.config.Tests.ClientSide {
		testRunners = append(testRunners, &tests.ClientSideTest{})
	}

	// Categoría APIT - APIs
	if ws.config.Tests.APISecurity {
		testRunners = append(testRunners, &tests.APISecurityTest{})
	}

	// Tests existentes que aún funcionan
	// Comentado temporalmente para debugging
	// if ws.config.Tests.InfoDisclosure {
	// 	testRunners = append(testRunners, &tests.InfoDisclosureTest{})
	// }

	return testRunners
}

// calculateSecurityScore calcula la puntuación de seguridad
func (ws *WebScanner) calculateSecurityScore(result *ScanResult) SecurityScore {
	fmt.Printf("DEBUG: Calculando score - Tests ejecutados: %d\n", result.TestsExecuted)

	if result.TestsExecuted == 0 {
		return SecurityScore{Value: 0, Risk: "Unknown"}
	}

	// Calcular puntuación base - solo contar tests que realmente se completaron
	completedTests := 0
	totalPoints := 0.0

	for _, test := range result.TestResults {
		fmt.Printf("DEBUG: Test '%s' - Status: %s, Severity: %s\n", test.TestName, test.Status, test.Severity)
		if test.Status != "Skipped" && test.Status != "Timeout" {
			completedTests++
			// Asignar puntos según el resultado
			switch test.Status {
			case "Passed":
				totalPoints += 1.0 // Punto completo
			case "Warning":
				totalPoints += 0.5 // Medio punto para warnings
			case "Failed":
				totalPoints += 0.0 // Sin puntos para fallos
			}
		}
	}

	fmt.Printf("DEBUG: Tests completados: %d, Puntos totales: %.1f\n", completedTests, totalPoints)

	var baseScore float64
	if completedTests > 0 {
		baseScore = (totalPoints / float64(completedTests)) * 10
	} else {
		// Si no hay tests completados, usar una puntuación baja pero no 0
		baseScore = 2.0
	}

	fmt.Printf("DEBUG: Score base: %.2f\n", baseScore)

	// Aplicar penalizaciones por severidad de tests fallidos
	for _, test := range result.TestResults {
		if test.Status == "Failed" {
			fmt.Printf("DEBUG: Aplicando penalización para test fallido '%s' - Severity: %s\n", test.TestName, test.Severity)
			switch test.Severity {
			case "Critical":
				baseScore -= 1.5 // Reducir penalización crítica
				fmt.Printf("DEBUG: Penalización Critical: -1.5, nuevo score: %.2f\n", baseScore)
			case "High":
				baseScore -= 1.0 // Reducir penalización alta
				fmt.Printf("DEBUG: Penalización High: -1.0, nuevo score: %.2f\n", baseScore)
			case "Medium":
				baseScore -= 0.5 // Reducir penalización media
				fmt.Printf("DEBUG: Penalización Medium: -0.5, nuevo score: %.2f\n", baseScore)
			case "Low":
				baseScore -= 0.2 // Reducir penalización baja
				fmt.Printf("DEBUG: Penalización Low: -0.2, nuevo score: %.2f\n", baseScore)
			}
		}
	}

	// Penalización mínima por tests saltados (el usuario decidió saltarlos)
	skippedCount := 0
	for _, test := range result.TestResults {
		if test.Status == "Skipped" || test.Status == "Timeout" {
			skippedCount++
		}
	}

	// Reducir score mínimamente por tests no completados
	if skippedCount > 0 {
		penaltyPerSkipped := 0.1 // Penalización muy pequeña
		baseScore -= float64(skippedCount) * penaltyPerSkipped
		fmt.Printf("DEBUG: Penalización por %d tests saltados: -%.2f\n", skippedCount, float64(skippedCount)*penaltyPerSkipped)
	}

	// Asegurar que la puntuación esté entre 0 y 10
	if baseScore < 0 {
		baseScore = 0
	}
	if baseScore > 10 {
		baseScore = 10
	}

	fmt.Printf("DEBUG: Score final: %.2f\n", baseScore)

	// Determinar nivel de riesgo
	var risk string
	switch {
	case baseScore >= 8:
		risk = "Bajo"
	case baseScore >= 6:
		risk = "Medio"
	case baseScore >= 4:
		risk = "Alto"
	default:
		risk = "Crítico"
	}

	fmt.Printf("DEBUG: Nivel de riesgo: %s\n", risk)

	return SecurityScore{
		Value: baseScore,
		Risk:  risk,
	}
}

// generateRecommendations genera recomendaciones basadas en los resultados
func (ws *WebScanner) generateRecommendations(result *ScanResult) []string {
	recommendations := []string{}

	fmt.Printf("DEBUG: Generando recomendaciones para %d tests\n", len(result.TestResults))

	for _, test := range result.TestResults {
		fmt.Printf("DEBUG: Test '%s' - Status: %s, Severity: %s\n", test.TestName, test.Status, test.Severity)
		if test.Status != "Passed" {
			// Usar strings.Contains para buscar patrones en el nombre del test
			testName := strings.ToLower(test.TestName)

			// Recomendaciones específicas por tipo de test
			if strings.Contains(testName, "sql") || strings.Contains(testName, "injection") {
				recommendations = append(recommendations, "Implementar sanitización de entrada y usar consultas preparadas para prevenir SQL injection")
			}

			if strings.Contains(testName, "xss") || strings.Contains(testName, "cross-site") {
				recommendations = append(recommendations, "Escapar salida HTML y validar entrada de usuario para prevenir XSS")
			}

			if strings.Contains(testName, "headers") || strings.Contains(testName, "security headers") {
				recommendations = append(recommendations, "Configurar headers de seguridad (Content-Security-Policy, HSTS, X-Frame-Options)")
			}

			if strings.Contains(testName, "ssl") || strings.Contains(testName, "tls") {
				recommendations = append(recommendations, "Actualizar certificados SSL y configurar HTTPS correctamente")
			}

			if strings.Contains(testName, "csrf") {
				recommendations = append(recommendations, "Implementar tokens CSRF en formularios sensibles")
			}

			if strings.Contains(testName, "directory") || strings.Contains(testName, "traversal") {
				recommendations = append(recommendations, "Validar rutas de archivos y restringir acceso a directorios")
			}

			if strings.Contains(testName, "brute") || strings.Contains(testName, "force") {
				recommendations = append(recommendations, "Implementar rate limiting y políticas de contraseñas fuertes")
			}

			if strings.Contains(testName, "file") && strings.Contains(testName, "upload") {
				recommendations = append(recommendations, "Validar tipos de archivo y restringir ejecución de uploads")
			}

			if strings.Contains(testName, "session") {
				recommendations = append(recommendations, "Configurar cookies de sesión con flags HttpOnly, Secure y SameSite")
			}

			if strings.Contains(testName, "configuration") {
				recommendations = append(recommendations, "Revisar configuración del servidor y deshabilitar métodos HTTP innecesarios")
			}

			if strings.Contains(testName, "cors") {
				recommendations = append(recommendations, "Configurar CORS de forma segura, evitar wildcard (*) con credenciales")
			}

			if strings.Contains(testName, "connectivity") || strings.Contains(testName, "basic") {
				recommendations = append(recommendations, "Verificar configuración básica del servidor y headers de respuesta")
			}

			if strings.Contains(testName, "client") {
				recommendations = append(recommendations, "Implementar Content Security Policy para protección del lado cliente")
			}

			if strings.Contains(testName, "api") {
				recommendations = append(recommendations, "Implementar autenticación y autorización adecuada en APIs")
			}

			// Recomendaciones por severidad
			if test.Severity == "Critical" {
				recommendations = append(recommendations, "⚠️ CRÍTICO: Corregir inmediatamente - vulnerabilidad de alto riesgo detectada")
			} else if test.Severity == "High" {
				recommendations = append(recommendations, "⚡ ALTO: Priorizar corrección - vulnerabilidad importante detectada")
			}
		}
	}

	// Agregar recomendaciones generales basadas en la puntuación
	if result.SecurityScore.Value <= 3 {
		recommendations = append(recommendations, "🔴 Realizar auditoría completa de seguridad - múltiples vulnerabilidades detectadas")
	} else if result.SecurityScore.Value <= 6 {
		recommendations = append(recommendations, "🟡 Revisar y corregir vulnerabilidades identificadas")
	}

	// Remover duplicados
	seen := make(map[string]bool)
	uniqueRecommendations := []string{}
	for _, rec := range recommendations {
		if !seen[rec] {
			seen[rec] = true
			uniqueRecommendations = append(uniqueRecommendations, rec)
		}
	}

	return uniqueRecommendations
}

// getTestName obtiene el nombre de un test runner por su tipo
func getTestName(testRunner TestRunner) string {
	switch tr := testRunner.(type) {
	case *tests.BasicTest:
		return "Basic Connectivity"
	case *tests.AdvancedSQLInjectionTest:
		return "Advanced SQL Injection"
	case *tests.SQLInjectionTest:
		return "SQL Injection"
	case *tests.AdvancedXSSTest:
		return "Advanced XSS"
	case *tests.XSSTest:
		return "XSS"
	case *tests.AdvancedSecurityHeadersTest:
		return "Advanced Security Headers"
	case *tests.AdvancedDirectoryTraversalTest:
		return "Advanced Directory Traversal"
	case *tests.InfoGatheringTest:
		return "Information Gathering"
	case *tests.DirectoryEnumerationTest:
		return "Directory Enumeration"
	case *tests.HTTPMethodsTest:
		return "HTTP Methods"
	case *tests.ConfigurationTest:
		return "Configuration"
	case *tests.DefaultPagesTest:
		return "Default Pages"
	case *tests.ErrorLeakageTest:
		return "Error Leakage"
	case *tests.IdentityManagementTest:
		return "Identity Management"
	case *tests.UserEnumerationTest:
		return "User Enumeration"
	case *tests.AuthorizationTest:
		return "Authorization"
	case *tests.DirectObjectReferenceTest:
		return "Direct Object Reference"
	case *tests.SessionMgmtTest:
		return "Session Management"
	case *tests.InputValidationTest:
		return "Input Validation"
	case *tests.DataValidationTest:
		return "Data Validation"
	case *tests.CryptographyTest:
		return "Cryptography"
	case *tests.BusinessLogicTest:
		return "Business Logic"
	case *tests.ClientSideTest:
		return "Client Side"
	case *tests.APISecurityTest:
		return "API Security"
	default:
		// Usar reflexión como fallback para obtener el nombre del tipo
		return fmt.Sprintf("Unknown Test (%T)", tr)
	}
}

// ScanOptions contiene las opciones para configurar un escaneo
type ScanOptions struct {
	TargetURL        string
	ConfigFile       string
	Verbose          bool
	Concurrent       int
	Timeout          time.Duration
	UseAdvancedTests bool
	EnabledTests     map[string]bool // mapa de test_id -> enabled
	SkipChannel      chan bool       // canal para recibir comandos de skip (opcional)
}

// CreateScanConfig crea una configuración de scanner unificada
func CreateScanConfig(options ScanOptions) (*config.Config, error) {
	// Cargar configuración base desde archivo
	cfg, err := config.LoadConfig(options.ConfigFile)
	if err != nil {
		// Si no se puede cargar, usar configuración por defecto
		cfg = config.DefaultConfig()
	}

	// Sobrescribir con opciones proporcionadas
	if options.Concurrent > 0 {
		cfg.Concurrent = options.Concurrent
	}
	if options.Timeout > 0 {
		cfg.Timeout = options.Timeout
	}
	cfg.Verbose = options.Verbose
	cfg.Tests.UseAdvancedTests = options.UseAdvancedTests

	// Configurar tests habilitados si se proporcionan
	if options.EnabledTests != nil {
		for testID, enabled := range options.EnabledTests {
			cfg.SetTestEnabled(testID, enabled)
		}
	}

	return cfg, nil
}

// ExecuteScan ejecuta un escaneo completo con las opciones especificadas
func ExecuteScan(options ScanOptions) (*ScanResult, error) {
	// Crear configuración
	cfg, err := CreateScanConfig(options)
	if err != nil {
		return nil, fmt.Errorf("error creando configuración: %w", err)
	}

	// Crear scanner
	webScanner := NewWebScanner(cfg)

	// Ejecutar escaneo con canal de skip si está disponible
	result := webScanner.ScanURLWithOptions(options.TargetURL, options.SkipChannel)

	// Completar información del resultado
	result.URL = options.TargetURL
	result.ScanDate = time.Now()

	return result, nil
}
