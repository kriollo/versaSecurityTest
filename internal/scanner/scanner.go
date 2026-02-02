package scanner

import (
	"context"
	"fmt"
	"math"
	"net/url"
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
	config    *config.Config
	payloads  *config.PayloadConfig
	client    tests.HTTPClient
	discovery *tests.DiscoveryResult
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
	return ws.ScanURLWithOptions(targetURL, nil, nil)
}

// ScanURLWithOptions ejecuta el escaneo con opciones adicionales
func (ws *WebScanner) ScanURLWithOptions(targetURL string, skipChannel chan bool, progressCallback ProgressCallback) *ScanResult {
	// Validar URL
	_, err := url.Parse(targetURL)
	if err != nil {
		return &ScanResult{
			URL: targetURL,
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

	startTime := time.Now()

	// FASE 1: Descubrimiento (Spidering/Crawling)
	fmt.Printf("\n🕷️  Iniciando fase de descubrimiento para: %s\n", targetURL)
	crawler := NewCrawler(ws.client)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	discovery, err := crawler.Discover(ctx, targetURL)
	if err != nil {
		fmt.Printf("⚠️  Error en descubrimiento: %v. Usando endpoint base.\n", err)
		discovery = &tests.DiscoveryResult{
			BaseURL: targetURL,
			Endpoints: map[string]*tests.EndpointInfo{
				"/": {Path: "/", Methods: []string{"GET"}},
			},
		}
	}
	ws.discovery = discovery
	fmt.Printf("✅ Descubrimiento completado: %d endpoints encontrados\n", len(discovery.Endpoints))

	// Variables para progreso
	completedTests := 0
	var progressMutex sync.Mutex
	var resultMutex sync.Mutex

	showProgress := func(testName string, completed, total int) {
		progressMutex.Lock()
		defer progressMutex.Unlock()

		if progressCallback != nil {
			progressCallback(testName, completed, total)
		}

		elapsed := time.Since(startTime)
		percent := float64(completed) / float64(total) * 100
		fmt.Printf("\r🔍 [%s] Test: %s | Progreso: %.1f%% [%d/%d] | Tiempo: %v | Hilos: %d",
			time.Now().Format("15:04:05"), testName, percent, completed, total, elapsed.Round(time.Second), ws.config.Concurrent)
	}

	// Fase de ejecución de tests
	testRunners := ws.getEnabledTests()
	result.TestsExecuted = len(testRunners)

	fmt.Printf("\n🚀 Iniciando ejecución de %d categorías de tests con %d hilos\n", len(testRunners), ws.config.Concurrent)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	concurrency := ws.config.Concurrent
	if concurrency <= 0 {
		concurrency = 1
	}

	testJobs := make(chan TestRunner, len(testRunners))
	testResults := make(chan tests.TestResult, len(testRunners))
	workerWg := sync.WaitGroup{}

	globalTimeout := time.Duration(ws.config.Timeout)
	globalCtx, globalCancel := context.WithTimeout(context.Background(), globalTimeout)
	defer globalCancel()

	// Lanzar workers
	for i := 0; i < concurrency; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for runner := range testJobs {
				select {
				case <-globalCtx.Done():
					return
				default:
				}

				// Si el test soporta descubrimiento, pasarle la info
				// (Por ahora refactorizamos los tests para que usen la info de ws en scanners futuros
				// o pasamos la info si el runner lo soporta via type assertion)

				// Ejecutar test
				res := runner.Run(targetURL, ws.client, ws.payloads)

				// Si es un test avanzado, le pasamos los endpoints descubiertos si podemos
				// Para esta implementación, los tests avanzados deberían ser inyectados con la data
				// Pero para mantener compatibilidad con la interfaz Run, lo manejaremos internamente

				testResults <- res
			}
		}()
	}

	// Enviar trabajos
	go func() {
		for _, runner := range testRunners {
			testJobs <- runner
		}
		close(testJobs)
	}()

	// Recolectar resultados
	go func() {
		workerWg.Wait()
		close(testResults)
	}()

	for tr := range testResults {
		resultMutex.Lock()
		result.TestResults = append(result.TestResults, tr)
		completedTests++

		switch tr.Status {
		case "Passed":
			result.TestsPassed++
		case "Skipped":
			result.TestsSkipped++
		case "Timeout":
			result.TestsTimeout++
		default:
			result.TestsFailed++
		}
		resultMutex.Unlock()

		showProgress(tr.TestName, completedTests, len(testRunners))
	}

	fmt.Printf("\n")
	result.Duration = time.Since(startTime)
	result.SecurityScore = ws.calculateSecurityScore(result)
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
			// Test avanzado con técnicas de evasión y descubrimiento
			testRunners = append(testRunners, &tests.AdvancedSQLInjectionTest{Discovery: ws.discovery})
		} else {
			// Test básico
			testRunners = append(testRunners, &tests.SQLInjectionTest{})
		}
	}

	// Tests de XSS (avanzados si está habilitado)
	if ws.config.Tests.XSS {
		if ws.config.Tests.UseAdvancedTests {
			// Test avanzado con múltiples técnicas de bypass
			testRunners = append(testRunners, &tests.AdvancedXSSTest{Discovery: ws.discovery})
		} else {
			// Test básico
			testRunners = append(testRunners, &tests.XSSTest{})
		}
	}

	// Nuevo Test de SSRF
	if ws.config.Tests.SSRF || ws.config.Tests.UseAdvancedTests {
		testRunners = append(testRunners, &tests.SSRFTest{Discovery: ws.discovery})
	}

	// Nuevo Test de Open Redirect
	if ws.config.Tests.OpenRedirect || ws.config.Tests.UseAdvancedTests {
		testRunners = append(testRunners, &tests.OpenRedirectTest{Discovery: ws.discovery})
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

	// Contar tests según su resultado
	passedCount := 0
	warningCount := 0
	failedCount := 0
	completedTests := 0
	criticalFailures := 0
	highFailures := 0
	mediumFailures := 0
	lowFailures := 0

	for _, test := range result.TestResults {
		fmt.Printf("DEBUG: Test '%s' - Status: %s, Severity: %s\n", test.TestName, test.Status, test.Severity)
		if test.Status != "Skipped" && test.Status != "Timeout" {
			completedTests++
			switch test.Status {
			case "Passed":
				passedCount++
			case "Warning":
				warningCount++
			case "Failed":
				failedCount++
				// Contar failures por severidad
				switch test.Severity {
				case "Critical":
					criticalFailures++
				case "High":
					highFailures++
				case "Medium":
					mediumFailures++
				case "Low":
					lowFailures++
				}
			}
		}
	}

	fmt.Printf("DEBUG: Passed: %d, Warning: %d, Failed: %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
		passedCount, warningCount, failedCount, criticalFailures, highFailures, mediumFailures, lowFailures)

	if completedTests == 0 {
		return SecurityScore{Value: 2.0, Risk: "Unknown"}
	}

	// Calcular score base como porcentaje de éxito
	successRate := float64(passedCount+warningCount) / float64(completedTests)
	baseScore := successRate * 10

	fmt.Printf("DEBUG: Success rate: %.2f%%, Score base inicial: %.2f\n", successRate*100, baseScore)

	// Aplicar penalizaciones moderadas por severity - pero sin eliminar todo el progreso
	// Las penalizaciones son proporcionales y no excesivas
	totalPenalty := 0.0
	if criticalFailures > 0 {
		penalty := float64(criticalFailures) * 0.8 // Penalización moderada por crítico
		totalPenalty += penalty
		fmt.Printf("DEBUG: Penalización por %d failures críticos: -%.2f\n", criticalFailures, penalty)
	}
	if highFailures > 0 {
		penalty := float64(highFailures) * 0.5 // Penalización moderada por alto
		totalPenalty += penalty
		fmt.Printf("DEBUG: Penalización por %d failures altos: -%.2f\n", highFailures, penalty)
	}
	if mediumFailures > 0 {
		penalty := float64(mediumFailures) * 0.3 // Penalización pequeña por medio
		totalPenalty += penalty
		fmt.Printf("DEBUG: Penalización por %d failures medios: -%.2f\n", mediumFailures, penalty)
	}
	if lowFailures > 0 {
		penalty := float64(lowFailures) * 0.1 // Penalización mínima por bajo
		totalPenalty += penalty
		fmt.Printf("DEBUG: Penalización por %d failures bajos: -%.2f\n", lowFailures, penalty)
	}

	fmt.Printf("DEBUG: Penalización total: -%.2f\n", totalPenalty)
	baseScore -= totalPenalty

	// Penalización muy pequeña por tests saltados
	skippedCount := result.TestsSkipped + result.TestsTimeout
	if skippedCount > 0 {
		skippedPenalty := float64(skippedCount) * 0.05 // Penalización muy pequeña
		baseScore -= skippedPenalty
		fmt.Printf("DEBUG: Penalización por %d tests saltados: -%.2f\n", skippedCount, skippedPenalty)
	}

	// Establecer un mínimo razonable: si pasaron algunos tests, el score no puede ser 0
	minScore := 0.0
	if passedCount > 0 {
		// Score mínimo basado en cuántos tests pasaron
		minScore = math.Max(1.0, float64(passedCount)*0.3)
		fmt.Printf("DEBUG: Score mínimo calculado: %.2f (basado en %d tests pasados)\n", minScore, passedCount)
	}

	// Aplicar límites
	if baseScore < minScore {
		baseScore = minScore
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

// ProgressCallback define la función de callback para reportar progreso
type ProgressCallback func(testName string, completed int, total int)

// ScanOptions contiene las opciones para configurar un escaneo
type ScanOptions struct {
	TargetURL        string
	ConfigFile       string
	Verbose          bool
	Concurrent       int
	Timeout          time.Duration
	UseAdvancedTests bool
	EnabledTests     map[string]bool  // mapa de test_id -> enabled
	SkipChannel      chan bool        // canal para recibir comandos de skip (opcional)
	ProgressCallback ProgressCallback // callback para reportar progreso (opcional)
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

	// Ejecutar escaneo con las opciones completas (incluye callback y skip channel)
	result := webScanner.ScanURLWithOptions(options.TargetURL, options.SkipChannel, options.ProgressCallback)

	// Completar información del resultado
	result.URL = options.TargetURL
	result.ScanDate = time.Now()

	return result, nil
}

// minDuration retorna la menor de dos duraciones
func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
