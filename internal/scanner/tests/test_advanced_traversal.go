package tests

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	"github.com/versaSecurityTest/internal/config"
)

// AdvancedDirectoryTraversalTest - Test exhaustivo de Directory Traversal
type AdvancedDirectoryTraversalTest struct {
	Discovery *DiscoveryResult
}

// Run ejecuta tests completos de directory traversal
func (t *AdvancedDirectoryTraversalTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "Advanced Directory Traversal Test",
		Status:      "Passed",
		Description: "No se detectaron vulnerabilidades de directory traversal",
		Severity:    "None",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	// PAYLOADS EXHAUSTIVOS (reducidos para el ejemplo)
	traversalPayloads := []string{
		"../../../etc/passwd",
		"../../../../etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"/etc/passwd",
		"../../.env",
	}

	var endpointsToTest []string
	var paramsToTest []string

	if t.Discovery != nil && len(t.Discovery.Endpoints) > 0 {
		for _, info := range t.Discovery.Endpoints {
			endpointsToTest = append(endpointsToTest, info.Path)
			paramsToTest = append(paramsToTest, info.Params...)
		}
	} else {
		// Fallback
		endpointsToTest = []string{"/download", "/file", "/view"}
		paramsToTest = []string{"file", "path", "filename"}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var vulnerabilitiesFound int

	semaphore := make(chan struct{}, 5)

	for _, endpoint := range endpointsToTest {
		for _, param := range paramsToTest {
			for _, payload := range traversalPayloads {
				wg.Add(1)
				go func(e, p, pay string) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					testURL := fmt.Sprintf("%s%s?%s=%s", targetURL, e, p, url.QueryEscape(pay))

					resp, err := client.Get(testURL)
					if err != nil {
						return
					}
					defer resp.Body.Close()

					body, _ := io.ReadAll(resp.Body)

					traversalVuln := t.analyzeTraversalResponse(resp.StatusCode, string(body), pay)
					if traversalVuln.IsVulnerable {
						mu.Lock()
						vulnerabilitiesFound++
						result.Evidence = append(result.Evidence, Evidence{
							Type:        "Directory Traversal",
							URL:         testURL,
							Payload:     pay,
							StatusCode:  resp.StatusCode,
							Response:    traversalVuln.Evidence,
							Description: traversalVuln.Description,
							Severity:    traversalVuln.Severity,
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
		result.Description = fmt.Sprintf("CRÍTICO: Se detectaron %d vulnerabilidades de directory traversal", vulnerabilitiesFound)
	}

	return result
}

// TraversalVulnerability estructura para análisis de directory traversal
type TraversalVulnerability struct {
	IsVulnerable bool
	Description  string
	Evidence     string
	Severity     string
}

// analyzeTraversalResponse analiza la respuesta en busca de directory traversal
func (t *AdvancedDirectoryTraversalTest) analyzeTraversalResponse(statusCode int, responseText, payload string) TraversalVulnerability {
	responseLower := strings.ToLower(responseText)

	// PATRONES DE ARCHIVOS SISTEMA UNIX/LINUX
	unixPatterns := []struct {
		pattern     string
		description string
		severity    string
	}{
		{"root:x:0:0:", "/etc/passwd accedido - usuarios del sistema expuestos", "Critical"},
		{"daemon:x:", "/etc/passwd accedido - cuentas del sistema visibles", "Critical"},
		{"bin:x:1:1:", "/etc/passwd accedido - estructura de usuarios comprometida", "Critical"},
		{"root:$", "/etc/shadow accedido - hashes de contraseñas expuestos", "Critical"},
		{"# localhost", "/etc/hosts accedido - configuración de red expuesta", "High"},
		{"127.0.0.1", "/etc/hosts accedido - mapeo de hosts visible", "High"},
		{"linux version", "/proc/version accedido - información del kernel expuesta", "Medium"},
		{"ubuntu", "/etc/issue accedido - información del sistema expuesta", "Medium"},
		{"debian", "/etc/issue accedido - información del sistema expuesta", "Medium"},
		{"welcome to", "/etc/motd accedido - mensaje del sistema visible", "Low"},
	}

	// PATRONES DE ARCHIVOS SISTEMA WINDOWS
	windowsPatterns := []struct {
		pattern     string
		description string
		severity    string
	}{
		{"[boot loader]", "boot.ini accedido - configuración de arranque expuesta", "Critical"},
		{"timeout=", "boot.ini accedido - parámetros de arranque visibles", "Critical"},
		{"# copyright (c) 1993-", "win.ini accedido - configuración de Windows expuesta", "High"},
		{"[fonts]", "win.ini accedido - configuración del sistema visible", "High"},
		{"[extensions]", "win.ini accedido - asociaciones de archivos expuestas", "High"},
		{"[mci extensions]", "system.ini accedido - configuración del sistema expuesta", "High"},
		{"[386enh]", "system.ini accedido - configuración avanzada visible", "High"},
		{"# localhost", "hosts (Windows) accedido - configuración DNS expuesta", "High"},
		{"files=", "config.sys accedido - configuración DOS expuesta", "Medium"},
		{"@echo off", "autoexec.bat accedido - scripts de arranque visibles", "Medium"},
	}

	// Buscar patrones Unix/Linux
	for _, pattern := range unixPatterns {
		if strings.Contains(responseLower, pattern.pattern) {
			return TraversalVulnerability{
				IsVulnerable: true,
				Description:  pattern.description,
				Evidence:     fmt.Sprintf("Patrón encontrado: '%s' en respuesta con payload '%s'", pattern.pattern, payload),
				Severity:     pattern.severity,
			}
		}
	}

	// Buscar patrones Windows
	for _, pattern := range windowsPatterns {
		if strings.Contains(responseLower, pattern.pattern) {
			return TraversalVulnerability{
				IsVulnerable: true,
				Description:  pattern.description,
				Evidence:     fmt.Sprintf("Patrón encontrado: '%s' en respuesta con payload '%s'", pattern.pattern, payload),
				Severity:     pattern.severity,
			}
		}
	}

	// PATRONES DE ARCHIVOS WEB COMUNES
	webPatterns := []struct {
		pattern     string
		description string
		severity    string
	}{
		{"<?php", "Archivo PHP source code accedido", "High"},
		{"database_password", "Archivo de configuración con credenciales accedido", "Critical"},
		{"mysql_connect", "Configuración de base de datos expuesta", "Critical"},
		{"password", "Archivo con posibles credenciales accedido", "High"},
		{"secret_key", "Claves secretas expuestas en archivo de configuración", "Critical"},
		{"api_key", "API keys expuestas en archivos", "High"},
		{"define('db_", "Configuración de WordPress accedida", "High"},
		{"$database", "Variables de base de datos expuestas", "High"},
		{"allowoverride", ".htaccess accedido - configuración Apache expuesta", "Medium"},
		{"rewriterule", ".htaccess accedido - reglas de reescritura visibles", "Medium"},
	}

	// Buscar patrones de archivos web
	for _, pattern := range webPatterns {
		if strings.Contains(responseLower, pattern.pattern) {
			return TraversalVulnerability{
				IsVulnerable: true,
				Description:  pattern.description,
				Evidence:     fmt.Sprintf("Patrón encontrado: '%s' en respuesta con payload '%s'", pattern.pattern, payload),
				Severity:     pattern.severity,
			}
		}
	}

	// ANÁLISIS POR STATUS CODE Y LONGITUD
	if statusCode == 200 && len(responseText) > 100 {
		// Si el payload contiene rutas conocidas y obtenemos contenido
		suspiciousPaths := []string{"etc/passwd", "windows/win.ini", "etc/shadow", "boot.ini", "config.php", "web.config"}
		for _, path := range suspiciousPaths {
			if strings.Contains(strings.ToLower(payload), path) {
				return TraversalVulnerability{
					IsVulnerable: true,
					Description:  fmt.Sprintf("Posible acceso a archivo del sistema: %s", path),
					Evidence:     fmt.Sprintf("Status 200 con contenido (%d chars) para payload: %s", len(responseText), payload),
					Severity:     "Medium",
				}
			}
		}
	}

	// DETECCIÓN DE ERRORES REVELADORES
	errorPatterns := []string{
		"no such file or directory", "file not found", "access denied",
		"permission denied", "cannot open file", "invalid path",
		"path not found", "directory not found", "file does not exist",
	}

	for _, errorPattern := range errorPatterns {
		if strings.Contains(responseLower, errorPattern) && strings.Contains(payload, "../") {
			return TraversalVulnerability{
				IsVulnerable: true,
				Description:  "Error del sistema revelado - posible directory traversal",
				Evidence:     fmt.Sprintf("Error del sistema: '%s' con payload: %s", errorPattern, payload),
				Severity:     "Low",
			}
		}
	}

	return TraversalVulnerability{IsVulnerable: false}
}
