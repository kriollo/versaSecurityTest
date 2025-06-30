package scanner

import (
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
	URL           string                `json:"url"`
	ScanDate      time.Time             `json:"scan_date"`
	Duration      time.Duration         `json:"duration"`
	TestsExecuted int                   `json:"tests_executed"`
	TestsPassed   int                   `json:"tests_passed"`
	TestsFailed   int                   `json:"tests_failed"`
	SecurityScore SecurityScore         `json:"security_score"`
	TestResults   []tests.TestResult    `json:"test_results"`
	Recommendations []string            `json:"recommendations"`
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
		TestResults: []tests.TestResult{},
		Recommendations: []string{},
	}

	// Variables para progreso
	startTime := time.Now()
	completedTests := 0
	var progressMutex sync.Mutex

	// Función para mostrar progreso
	showProgress := func(currentTest string, completed, total int) {
		progressMutex.Lock()
		defer progressMutex.Unlock()

		elapsed := time.Since(startTime)
		percent := float64(completed) / float64(total) * 100
		fmt.Printf("\r🔍 [%s] Test: %s | Progreso: %.1f%% [%d/%d] | Tiempo: %v",
			time.Now().Format("15:04:05"), currentTest, percent, completed, total, elapsed.Round(time.Second))
	}

	// Canal para recopilar resultados de tests
	resultsChan := make(chan tests.TestResult, 20)
	var wg sync.WaitGroup

	// Test de conectividad básica
	if ws.config.Verbose {
		fmt.Printf("🔍 Verificando conectividad con %s...\n", targetURL)
	}

	// Ejecutar tests habilitados
	testRunners := ws.getEnabledTests()
	result.TestsExecuted = len(testRunners)

	for _, testRunner := range testRunners {
		wg.Add(1)
		go func(tr TestRunner) {
			defer wg.Done()
			testResult := tr.Run(targetURL, ws.client, ws.payloads)
			resultsChan <- testResult
		}(testRunner)
	}

	// Cerrar canal cuando todos los tests terminen
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Mostrar progreso inicial
	showProgress("Iniciando escaneo...", 0, len(testRunners))

	// Recopilar resultados
	for testResult := range resultsChan {
		result.TestResults = append(result.TestResults, testResult)

		if testResult.Status == "Passed" {
			result.TestsPassed++
		} else {
			result.TestsFailed++
		}

		// Actualizar progreso
		completedTests++
		showProgress(testResult.TestName, completedTests, len(testRunners))

		if ws.config.Verbose {
			status := "✅"
			if testResult.Status != "Passed" {
				status = "❌"
			}
			fmt.Printf("\n%s %s: %s", status, testResult.TestName, testResult.Description)
		}
	}

	// Finalizar línea de progreso
	fmt.Printf("\n")

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

	// Calcular puntuación base
	baseScore := float64(result.TestsPassed) / float64(result.TestsExecuted) * 10

	// Aplicar penalizaciones por severidad
	for _, test := range result.TestResults {
		if test.Status != "Passed" {
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
