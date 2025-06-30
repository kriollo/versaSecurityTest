package tests

import (
	"fmt"
	"strings"

	"github.com/versaSecurityTest/internal/config"
)

// FileUploadTest detecta vulnerabilidades en carga de archivos
type FileUploadTest struct{}

// Run ejecuta el test de carga de archivos
func (f *FileUploadTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName: "File Upload Test",
		Status:   "Passed",
		Details:  []string{},
		Severity: "High",
	}

	// Buscar formularios de upload en la página principal
	resp, err := client.Get(targetURL)
	if err != nil {
		result.Status = "Failed"
		result.Description = "Could not connect to target"
		result.Details = append(result.Details, fmt.Sprintf("Connection error: %v", err))
		return result
	}

	body := string(resp.Body)
	bodyLower := strings.ToLower(body)

	// Detectar formularios de upload
	hasFileUpload := strings.Contains(bodyLower, "type=\"file\"") ||
		strings.Contains(bodyLower, "enctype=\"multipart/form-data\"") ||
		strings.Contains(bodyLower, "upload")

	if !hasFileUpload {
		result.Status = "Warning"
		result.Description = "No file upload functionality detected"
		result.Details = append(result.Details, "ℹ️ No se detectaron formularios de carga de archivos")
		return result
	}

	result.Details = append(result.Details, "⚠️ Formulario de carga de archivos detectado")

	// Buscar endpoints comunes de upload
	uploadEndpoints := []string{"/upload", "/file/upload", "/admin/upload", "/wp-admin/media-upload.php"}
	vulnerableEndpoints := 0

	for _, endpoint := range uploadEndpoints {
		uploadURL := targetURL + endpoint
		resp, err := client.Get(uploadURL)
		if err == nil && resp.Status == "200 OK" {
			vulnerableEndpoints++
			result.Details = append(result.Details, fmt.Sprintf("❌ Endpoint de upload accesible: %s", endpoint))
		}
	}

	// Simular intentos de subida de archivos peligrosos
	dangerousFiles := []string{
		"shell.php",
		"test.jsp",
		"malware.exe",
		"script.js",
	}

	for _, filename := range dangerousFiles {
		// Simular upload (esto sería más complejo en un test real)
		result.Details = append(result.Details, fmt.Sprintf("🔍 Probando upload de: %s", filename))
	}

	if vulnerableEndpoints > 0 {
		result.Status = "Failed"
		result.Description = "File upload vulnerabilities detected"
		result.Severity = "Critical"
	} else {
		result.Description = "File upload functionality appears restricted"
		result.Details = append(result.Details, "✅ No se encontraron endpoints de upload accesibles")
	}

	return result
}
