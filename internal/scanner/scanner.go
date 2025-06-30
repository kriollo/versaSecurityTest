package scanner

import (
	"context"
	"fmt"
	"net/url"
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
	URL             string                `json:"url"`
	ScanDate        time.Time             `json:"scan_date"`
	Duration        time.Duration         `json:"duration"`
	TestsExecuted   int                   `json:"tests_executed"`
	TestsPassed     int                   `json:"tests_passed"`
	TestsFailed     int                   `json:"tests_failed"`
	TestsSkipped    int                   `json:"tests_skipped"`
	TestsTimeout    int                   `json:"tests_timeout"`
	SecurityScore   SecurityScore         `json:"security_score"`
	TestResults     []tests.TestResult    `json:"test_results"`
	Recommendations []string              `json:"recommendations"`
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
		fmt.Printf("\r🔍 [%s] Test: %s | Progreso: %.1f%% [%d/%d] | Tiempo: %v | [S]altar test",
			time.Now().Format("15:04:05"), testName, percent, completed, total, elapsed.Round(time.Second))
	}

	// Función para detectar tecla de salto (asíncrona)
	skipChan := make(chan bool, 1)
	go func() {
		for {
			var input string
			fmt.Scanln(&input)
			if input == "s" || input == "S" || input == "skip" {
				select {
				case skipChan <- true:
				default:
					// Canal lleno, ignorar
				}
			}
		}
	}()

	// Ejecutar tests habilitados
	testRunners := ws.getEnabledTests()
	result.TestsExecuted = len(testRunners)

	// Mostrar instrucciones iniciales
	fmt.Printf("\n💡 Durante el escaneo, presiona 'S' + Enter para saltar al siguiente test\n")
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
		testName := fmt.Sprintf("Test %d/%d", i+1, len(testRunners))

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
					TestName:    fmt.Sprintf("%s (Cancelado por usuario)", testName),
					Status:      "Skipped",
					Description: fmt.Sprintf("Test cancelado después de %v", time.Since(testStartTime).Round(time.Second)),
					Severity:    "Info",
					Details:     []string{"Usuario solicitó saltar al siguiente test"},
				}
				testCompleted = true
				fmt.Printf("\n⏭️  Test saltado por usuario\n")

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
	if result.TestsExecuted == 0 {
		return SecurityScore{Value: 0, Risk: "Unknown"}
	}

	// Calcular puntuación base - solo contar tests que realmente se completaron
	completedTests := 0
	passedTests := 0
	
	for _, test := range result.TestResults {
		if test.Status != "Skipped" && test.Status != "Timeout" {
			completedTests++
			if test.Status == "Passed" {
				passedTests++
			}
		}
	}

	var baseScore float64
	if completedTests > 0 {
		baseScore = float64(passedTests) / float64(completedTests) * 10
	} else {
		baseScore = 0
	}

	// Aplicar penalizaciones por severidad
	for _, test := range result.TestResults {
		if test.Status != "Passed" && test.Status != "Skipped" && test.Status != "Timeout" {
			switch test.Severity {
			case "Critical":
				baseScore -= 2.0
			case "High":
				baseScore -= 1.5
			case "Medium":
				baseScore -= 1.0
			case "Low":
				baseScore -= 0.5
			}
		}
	}

	// Penalización menor por tests saltados o timeout
	skippedCount := 0
	for _, test := range result.TestResults {
		if test.Status == "Skipped" || test.Status == "Timeout" {
			skippedCount++
		}
	}
	
	// Reducir score ligeramente por tests no completados
	if skippedCount > 0 {
		penaltyPerSkipped := 0.2
		baseScore -= float64(skippedCount) * penaltyPerSkipped
	}

	// Asegurar que la puntuación esté entre 0 y 10
	if baseScore < 0 {
		baseScore = 0
	}
	if baseScore > 10 {
		baseScore = 10
	}

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

	return SecurityScore{
		Value: baseScore,
		Risk:  risk,
	}
}

// generateRecommendations genera recomendaciones basadas en los resultados
func (ws *WebScanner) generateRecommendations(result *ScanResult) []string {
	recommendations := []string{}

	for _, test := range result.TestResults {
		if test.Status != "Passed" {
			switch test.TestName {
			case "SQL Injection":
				recommendations = append(recommendations, "Implementar sanitización de entrada y usar consultas preparadas")
			case "XSS":
				recommendations = append(recommendations, "Escapar salida HTML y validar entrada de usuario")
			case "HTTP Headers":
				recommendations = append(recommendations, "Configurar headers de seguridad (CSP, HSTS, X-Frame-Options)")
			case "SSL/TLS":
				recommendations = append(recommendations, "Actualizar certificados SSL y configurar HTTPS correctamente")
			case "CSRF":
				recommendations = append(recommendations, "Implementar tokens CSRF en formularios sensibles")
			case "Directory Traversal":
				recommendations = append(recommendations, "Validar rutas de archivos y restringir acceso a directorios")
			case "Brute Force":
				recommendations = append(recommendations, "Implementar rate limiting y políticas de contraseñas fuertes")
			case "File Upload":
				recommendations = append(recommendations, "Validar tipos de archivo y restringir ejecución de uploads")
			}
		}
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
