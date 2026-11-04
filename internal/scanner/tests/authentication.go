package tests

import (
	"fmt"
	"io"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// AuthenticationTest - Categoría ATHN (ATHN-01 a ATHN-06)
type AuthenticationTest struct{}

// Run ejecuta pruebas de vulnerabilidades en la autenticación
func (t *AuthenticationTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "ATHN-01: Authentication Testing",
		Status:      "Passed",
		Description: "Pruebas de seguridad en los mecanismos de autenticación",
		Severity:    "Info",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	// 1. ATHN-01: Verificar si las credenciales viajan sobre canal cifrado (HTTPS)
	isHTTPS := strings.HasPrefix(strings.ToLower(targetURL), "https://")
	isLocal := IsLocalTarget(targetURL)
	if !isHTTPS && !isLocal {
		result.Status = "Failed"
		result.Severity = "High"
		result.Description = "Credenciales transportadas sobre canal no cifrado (HTTP)"
		result.Details = append(result.Details, "❌ ATHN-01: El sitio utiliza HTTP. Las credenciales pueden ser interceptadas en tránsito.")
		result.Evidence = append(result.Evidence, Evidence{
			Type:        "Insecure Transport",
			URL:         targetURL,
			Description: "Uso de HTTP en lugar de HTTPS para autenticación",
			Severity:    "High",
		})
	} else if !isHTTPS && isLocal {
		result.Details = append(result.Details, "✅ ATHN-01: Objetivo local (localhost); HTTP no expone credenciales fuera del equipo.")
	} else {
		result.Details = append(result.Details, "✅ ATHN-01: El sitio utiliza HTTPS para el transporte de datos.")
	}

	// 2. Buscar formularios de login y analizar su seguridad
	resp, err := client.Get(targetURL)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)
	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "<form") {
		// Nota: ya NO se exige autocomplete="off" en campos de contraseña. La guía actual de OWASP lo
		// desaconseja: romper los gestores de contraseñas empeora la seguridad, no la mejora.

		// Buscar debilidades en la gestión de errores de autenticación
		// (Esto se ampliaría probando el login real)
	}

	// 3. Probar endpoints comunes susceptibles a autenticación débil o por defecto.
	// /admin se omite a propósito: es la propia página de login de muchos frameworks (versaWYS incluido),
	// así que un 200 ahí es esperado, no una falla.
	adminEndpoints := []struct {
		path string
		name string
	}{
		{"/manager/html", "Tomcat Manager"},
		{"/phpmyadmin", "phpMyAdmin"},
		{"/console", "Web Console"},
	}

	for _, endpoint := range adminEndpoints {
		testURL := targetURL + endpoint.path
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			result.Details = append(result.Details, fmt.Sprintf("⚠️ %s accesible en: %s", endpoint.name, endpoint.path))
			if result.Status == "Passed" {
				result.Status = "Warning"
				if result.Severity == "Info" {
					result.Severity = "Medium"
				}
			}
		}
	}

	if len(result.Details) == 0 {
		result.Description = "No se detectaron mecanismos de autenticación para analizar en la raíz"
	}

	return result
}
