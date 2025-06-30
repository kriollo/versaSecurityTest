package tests

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/versaSecurityTest/internal/config"
)

// SSLAnalysisTest analiza la configuración SSL/TLS
type SSLAnalysisTest struct{}

// Run ejecuta el test de análisis SSL/TLS
func (s *SSLAnalysisTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName: "SSL/TLS Analysis",
		Status:   "Passed",
		Details:  []string{},
		Severity: "Medium",
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Status = "Failed"
		result.Description = "Error parsing URL"
		result.Details = append(result.Details, fmt.Sprintf("URL parsing error: %v", err))
		return result
	}

	// Solo analizar HTTPS
	if parsedURL.Scheme != "https" {
		result.Status = "Warning"
		result.Description = "Site not using HTTPS"
		result.Details = append(result.Details, "El sitio no utiliza HTTPS - recomendado para seguridad")
		result.Severity = "High"
		return result
	}

	// Configurar conexión TLS para análisis
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false, // Queremos verificar certificados
	}

	// Obtener información del certificado
	host := parsedURL.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	conn, err := tls.Dial("tcp", host, tlsConfig)
	if err != nil {
		result.Status = "Failed"
		result.Description = "SSL/TLS connection failed"
		result.Details = append(result.Details, fmt.Sprintf("Error de conexión TLS: %v", err))
		result.Severity = "High"
		return result
	}
	defer conn.Close()

	// Analizar certificado
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		result.Status = "Failed"
		result.Description = "No certificate found"
		result.Details = append(result.Details, "No se encontró certificado SSL")
		result.Severity = "Critical"
		return result
	}

	cert := state.PeerCertificates[0]
	issues := []string{}
	warnings := []string{}

	// Verificar expiración del certificado
	now := time.Now()
	if cert.NotAfter.Before(now) {
		issues = append(issues, "Certificado expirado")
		result.Severity = "Critical"
	} else if cert.NotAfter.Before(now.AddDate(0, 0, 30)) {
		warnings = append(warnings, "Certificado expira en menos de 30 días")
	}

	// Verificar validez temporal
	if cert.NotBefore.After(now) {
		issues = append(issues, "Certificado aún no válido")
		result.Severity = "Critical"
	}

	// Verificar versión de TLS
	tlsVersion := ""
	switch state.Version {
	case tls.VersionTLS10:
		tlsVersion = "TLS 1.0 (Obsoleto)"
		issues = append(issues, "Usando TLS 1.0 - versión obsoleta e insegura")
		result.Severity = "High"
	case tls.VersionTLS11:
		tlsVersion = "TLS 1.1 (Obsoleto)"
		issues = append(issues, "Usando TLS 1.1 - versión obsoleta")
		result.Severity = "High"
	case tls.VersionTLS12:
		tlsVersion = "TLS 1.2 (Aceptable)"
		warnings = append(warnings, "TLS 1.2 es aceptable, pero TLS 1.3 es recomendado")
	case tls.VersionTLS13:
		tlsVersion = "TLS 1.3 (Recomendado)"
	default:
		tlsVersion = "Versión desconocida"
		issues = append(issues, "Versión de TLS desconocida")
	}

	// Verificar suite de cifrado
	cipherSuite := tls.CipherSuiteName(state.CipherSuite)
	if strings.Contains(strings.ToLower(cipherSuite), "rc4") ||
		strings.Contains(strings.ToLower(cipherSuite), "des") ||
		strings.Contains(strings.ToLower(cipherSuite), "md5") {
		issues = append(issues, "Suite de cifrado débil detectada")
		result.Severity = "High"
	}

	// Verificar información del certificado
	result.Details = append(result.Details, fmt.Sprintf("Emisor: %s", cert.Issuer.CommonName))
	result.Details = append(result.Details, fmt.Sprintf("Sujeto: %s", cert.Subject.CommonName))
	result.Details = append(result.Details, fmt.Sprintf("Válido desde: %s", cert.NotBefore.Format("2006-01-02")))
	result.Details = append(result.Details, fmt.Sprintf("Válido hasta: %s", cert.NotAfter.Format("2006-01-02")))
	result.Details = append(result.Details, fmt.Sprintf("Versión TLS: %s", tlsVersion))
	result.Details = append(result.Details, fmt.Sprintf("Suite de cifrado: %s", cipherSuite))

	// Verificar nombres alternativos del sujeto
	if len(cert.DNSNames) > 0 {
		result.Details = append(result.Details, fmt.Sprintf("DNS Names: %v", cert.DNSNames))
	}

	// Compilar resultado final
	if len(issues) > 0 {
		result.Status = "Failed"
		result.Description = "SSL/TLS security issues detected"
		result.Details = append(result.Details, "Problemas encontrados:")
		for _, issue := range issues {
			result.Details = append(result.Details, "  ❌ "+issue)
		}
	} else {
		result.Description = "SSL/TLS configuration appears secure"
	}

	if len(warnings) > 0 {
		if result.Status == "Passed" {
			result.Status = "Warning"
		}
		result.Details = append(result.Details, "Advertencias:")
		for _, warning := range warnings {
			result.Details = append(result.Details, "  ⚠️ "+warning)
		}
	}

	return result
}
