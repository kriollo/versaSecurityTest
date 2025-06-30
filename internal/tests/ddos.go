package tests

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/versaSecurityTest/internal/config"
	"github.com/versaSecurityTest/internal/types"
)

// DDoSTest realiza un test simulado de DDoS controlado
type DDoSTest struct{}

// Run ejecuta el test de DDoS simulado
func (t *DDoSTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) types.TestResult {
	result := types.TestResult{
		TestName:    "DDoS Simulation",
		Status:      "Passed",
		Description: "Test de resistencia a ataques DDoS simulados",
		Severity:    "None",
		Details:     []string{},
		Evidence:    []types.Evidence{},
	}

	// Número de requests concurrentes para el test
	const concurrentRequests = 20
	const requestsPerWorker = 10
	const maxDuration = 30 * time.Second

	// Canal para coordinar los workers
	responseChan := make(chan TestResponse, concurrentRequests*requestsPerWorker)
	var wg sync.WaitGroup

	startTime := time.Now()
	
	// Lanzar workers concurrentes
	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for j := 0; j < requestsPerWorker; j++ {
				// Verificar timeout global
				if time.Since(startTime) > maxDuration {
					return
				}
				
				resp, err := client.Get(targetURL)
				
				testResp := TestResponse{
					WorkerID:     workerID,
					RequestID:    j,
					StatusCode:   0,
					ResponseTime: time.Since(startTime),
					Error:        err,
				}
				
				if resp != nil {
					testResp.StatusCode = resp.StatusCode
					resp.Body.Close()
				}
				
				responseChan <- testResp
				
				// Pequeña pausa entre requests del mismo worker
				time.Sleep(100 * time.Millisecond)
			}
		}(i)
	}

	// Cerrar el canal cuando todos los workers terminen
	go func() {
		wg.Wait()
		close(responseChan)
	}()

	// Recopilar resultados
	var responses []TestResponse
	var successfulRequests, failedRequests, timeoutRequests int
	var totalResponseTime time.Duration

	for response := range responseChan {
		responses = append(responses, response)
		
		if response.Error != nil {
			failedRequests++
			result.Details = append(result.Details, 
				fmt.Sprintf("Worker %d, Request %d: Error - %v", 
					response.WorkerID, response.RequestID, response.Error))
		} else if response.StatusCode >= 200 && response.StatusCode < 400 {
			successfulRequests++
			totalResponseTime += response.ResponseTime
		} else if response.StatusCode >= 500 {
			timeoutRequests++
			result.Details = append(result.Details, 
				fmt.Sprintf("Worker %d, Request %d: Server Error %d", 
					response.WorkerID, response.RequestID, response.StatusCode))
		} else {
			successfulRequests++
		}
	}

	totalRequests := len(responses)
	successRate := float64(successfulRequests) / float64(totalRequests) * 100
	
	// Evaluar resultados
	if successRate < 50 {
		result.Status = "Failed"
		result.Severity = "High"
		result.Description = fmt.Sprintf("El servidor mostró signos de degradación bajo carga. Tasa de éxito: %.1f%%", successRate)
		
		result.Evidence = append(result.Evidence, types.Evidence{
			Type:        "Server Overload",
			Description: fmt.Sprintf("Bajo rendimiento detectado: %.1f%% de requests exitosos", successRate),
			Severity:    "High",
			URL:         targetURL,
		})
	} else if successRate < 80 {
		result.Status = "Warning"
		result.Severity = "Medium"
		result.Description = fmt.Sprintf("El servidor mostró alguna degradación bajo carga. Tasa de éxito: %.1f%%", successRate)
		
		result.Evidence = append(result.Evidence, types.Evidence{
			Type:        "Performance Degradation",
			Description: fmt.Sprintf("Rendimiento moderado: %.1f%% de requests exitosos", successRate),
			Severity:    "Medium",
			URL:         targetURL,
		})
	} else {
		result.Description = fmt.Sprintf("El servidor manejó bien la carga simulada. Tasa de éxito: %.1f%%", successRate)
	}

	// Agregar estadísticas detalladas
	avgResponseTime := time.Duration(0)
	if successfulRequests > 0 {
		avgResponseTime = totalResponseTime / time.Duration(successfulRequests)
	}

	result.Details = append(result.Details, []string{
		fmt.Sprintf("Total de requests enviados: %d", totalRequests),
		fmt.Sprintf("Requests exitosos: %d", successfulRequests),
		fmt.Sprintf("Requests fallidos: %d", failedRequests),
		fmt.Sprintf("Errores de servidor: %d", timeoutRequests),
		fmt.Sprintf("Tasa de éxito: %.1f%%", successRate),
		fmt.Sprintf("Tiempo promedio de respuesta: %v", avgResponseTime),
		fmt.Sprintf("Duración total del test: %v", time.Since(startTime)),
	}...)

	return result
}

// TestResponse representa la respuesta de un request individual
type TestResponse struct {
	WorkerID     int
	RequestID    int
	StatusCode   int
	ResponseTime time.Duration
	Error        error
}
