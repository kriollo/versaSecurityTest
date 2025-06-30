package tests

import (
	"fmt"

	"github.com/versaSecurityTest/internal/config"
)

// BruteForceTest detecta vulnerabilidades de fuerza bruta

type BruteForceTest struct{}

// Run ejecuta el test de fuerza bruta
func (b *BruteForceTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName: "Brute Force Test",
		Status:   "Passed",
		Details:  []string{},
		Severity: "High",
	}

	// Simulación básica de fuerza bruta a URLs de login comunes
	loginEndpoints := []string{"/login", "/admin", "/admin/login", "/wp-admin", "/user/login"}

	// Supuestos recursos de login para fuerza bruta
	var attemptCount int

	for _, endpoint := range loginEndpoints {
		loginURL := targetURL + endpoint
		for _, cred := range payloads.CommonCredentials {
			attemptCount++
			resp, _ := client.PostForm(loginURL, map[string]string{
				"username": cred.Username,
				"password": cred.Password,
			})

			// Si no hay invalid credentials, es peligroso
			if resp.Status == "200 OK" || resp.Status == "302 Found" {
				result.Status = "Failed"
				result.Details = append(result.Details, fmt.Sprintf("❌ Credenciales débiles aceptadas: %s:%s", cred.Username, cred.Password))
			}
		}
	}

	if result.Status == "Passed" {
		result.Description = fmt.Sprintf("No successful brute force attempts on %d attempts", attemptCount)
	} else {
		result.Description = fmt.Sprintf("Potential brute force vulnerability detected")
	}

	return result
}

