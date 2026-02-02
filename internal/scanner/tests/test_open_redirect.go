package tests

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/versaSecurityTest/internal/config"
)

// OpenRedirectTest - Test de redirecciones abiertas
type OpenRedirectTest struct {
	Discovery *DiscoveryResult
}

// Run ejecuta el test de Open Redirect
func (t *OpenRedirectTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "Open Redirect",
		Status:      "Passed",
		Description: "No se detectaron redirecciones abiertas peligrosas",
		Severity:    "None",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	redirectPayloads := []string{
		"//google.com",
		"https://google.com/%2f..",
		"//evil.com",
		"http://evil.com",
		"javaScript:alert(1)",
	}

	var endpointsToTest []string
	var paramsToTest []string

	if t.Discovery != nil && len(t.Discovery.Endpoints) > 0 {
		for _, info := range t.Discovery.Endpoints {
			endpointsToTest = append(endpointsToTest, info.Path)
			paramsToTest = append(paramsToTest, info.Params...)
		}
	} else {
		endpointsToTest = []string{"/redirect", "/login", "/logout", "/checkout"}
		paramsToTest = []string{"url", "next", "return", "redirect_to"}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	vulnerabilitiesFound := 0

	for _, endpoint := range endpointsToTest {
		for _, param := range paramsToTest {
			for _, payload := range redirectPayloads {
				wg.Add(1)
				go func(e, p, pay string) {
					defer wg.Done()
					testURL := fmt.Sprintf("%s%s?%s=%s", targetURL, e, p, url.QueryEscape(pay))

					// Necesitamos un cliente que no siga redirecciones para este test
					// Pero usaremos el status code y el header Location
					resp, err := client.Get(testURL)
					if err != nil {
						return
					}
					defer resp.Body.Close()

					location := resp.Header.Get("Location")
					if (resp.StatusCode >= 300 && resp.StatusCode < 400) && (strings.Contains(location, "google.com") || strings.Contains(location, "evil.com")) {
						mu.Lock()
						vulnerabilitiesFound++
						result.Evidence = append(result.Evidence, Evidence{
							Type:        "Open Redirect",
							URL:         testURL,
							Payload:     pay,
							StatusCode:  resp.StatusCode,
							Description: fmt.Sprintf("Redirección detectada a: %s", location),
							Severity:    "Medium",
						})
						mu.Unlock()
					}
				}(endpoint, param, payload)
			}
		}
	}

	wg.Wait()

	if vulnerabilitiesFound > 0 {
		result.Status = "Failed"
		result.Severity = "Medium"
		result.Description = fmt.Sprintf("Se detectaron %d vulnerabilidades de Open Redirect", vulnerabilitiesFound)
	}

	return result
}
