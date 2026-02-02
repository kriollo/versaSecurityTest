package tests

import (
	"fmt"
	"net/url"

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
			formData := url.Values{
				"username": {cred.Username},
				"password": {cred.Password},
			}
			resp, _ := client.PostForm(loginURL, formData)

			// Si no hay invalid credentials, es peligroso
			if resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 302) {
				result.Status = "Failed"
				result.Details = append(result.Details, "❌ Intento de fuerza bruta exitoso")
			}
		}
	}

	if result.Status == "Passed" {
		result.Description = fmt.Sprintf("No successful brute force attempts on %d attempts", attemptCount)
	} else {
		result.Description = "Potential brute force vulnerability detected"
	}

	return result
}
