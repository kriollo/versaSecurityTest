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

	// Recopilar resultados
	for testResult := range resultsChan {
		result.TestResults = append(result.TestResults, testResult)
		
		if testResult.Status == "Passed" {
			result.TestsPassed++
		} else {
			result.TestsFailed++
		}

		if ws.config.Verbose {
			status := "✅"
			if testResult.Status != "Passed" {
				status = "❌"
			}
			fmt.Printf("%s %s: %s\n", status, testResult.TestName, testResult.Description)
		}
	}

	// Calcular puntuación de seguridad
	result.SecurityScore = ws.calculateSecurityScore(result)

	// Generar recomendaciones
	result.Recommendations = ws.generateRecommendations(result)

	return result
}

// getEnabledTests retorna la lista de tests habilitados
func (ws *WebScanner) getEnabledTests() []TestRunner {
	var testRunners []TestRunner

	// Tests básicos disponibles
	testRunners = append(testRunners, &tests.BasicTest{})
	
	if ws.config.Tests.SQLInjection {
		testRunners = append(testRunners, &tests.SQLInjectionTest{})
	}
	if ws.config.Tests.XSS {
		testRunners = append(testRunners, &tests.XSSTest{})
	}

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
