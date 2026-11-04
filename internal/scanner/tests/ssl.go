package tests

import (
	"crypto/tls"
	"crypto/x509"
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
		if IsLocalTarget(targetURL) {
			result.Status = "Passed"
			result.Description = "SSL/TLS no aplica a localhost"
			result.Details = append(result.Details, "✅ Objetivo local (localhost): no se evalúa HTTPS/HSTS.")
			result.Severity = "Info"
			return result
		}
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

	// 1. Análisis de Versión TLS (Grado de Seguridad)
	tlsVersion := ""
	switch state.Version {
	case tls.VersionTLS10:
		tlsVersion = "TLS 1.0 (CRÍTICO: Obsoleto e Inseguro)"
		issues = append(issues, "TLS 1.0 detectado - vulnerable a ataques POODLE y BEAST")
		result.Severity = "Critical"
	case tls.VersionTLS11:
		tlsVersion = "TLS 1.1 (ALTO: Obsoleto)"
		issues = append(issues, "TLS 1.1 detectado - versión ya no recomendada por estándares de la industria")
		result.Severity = "High"
	case tls.VersionTLS12:
		tlsVersion = "TLS 1.2 (Aceptable)"
		warnings = append(warnings, "TLS 1.2 es el estándar actual, pero se recomienda migrar a TLS 1.3")
	case tls.VersionTLS13:
		tlsVersion = "TLS 1.3 (ÓPTIMO: Recomendado)"
	default:
		tlsVersion = fmt.Sprintf("Versión desconodida (0x%x)", state.Version)
	}

	// 2. Análisis de Cipher Suite (Cifrado)
	cipherSuite := tls.CipherSuiteName(state.CipherSuite)
	isWeak := false

	// Patrones de cifrados débiles o problemáticos
	weakPatterns := []string{"RC4", "DES", "3DES", "MD5", "EXPORT", "anon", "NULL"}
	for _, pattern := range weakPatterns {
		if strings.Contains(strings.ToUpper(cipherSuite), pattern) {
			isWeak = true
			issues = append(issues, fmt.Sprintf("Suite de cifrado insegura detectada: %s", cipherSuite))
			result.Severity = "High"
			break
		}
	}

	// Verificar si usa CBC sin ser AEAD (potencialmente vulnerable)
	if !isWeak && strings.Contains(cipherSuite, "CBC") {
		warnings = append(warnings, fmt.Sprintf("Uso de modo CBC en suite: %s (se recomiendan modos AEAD como GCM o Poly1305)", cipherSuite))
	}

	// 3. Verificación de Certificado
	now := time.Now()

	// Expiración
	if cert.NotAfter.Before(now) {
		issues = append(issues, "CERTIFICADO EXPIRADO - el sitio no es seguro para navegación")
		result.Severity = "Critical"
	} else if cert.NotAfter.Before(now.AddDate(0, 0, 15)) {
		issues = append(issues, fmt.Sprintf("Certificado expira muy pronto (en %v días)", int(cert.NotAfter.Sub(now).Hours()/24)))
		result.Severity = "High"
	} else if cert.NotAfter.Before(now.AddDate(0, 0, 45)) {
		warnings = append(warnings, "Certificado próximo a expirar (menos de 45 días)")
	}

	// Algoritmo de Firma
	if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.DSAWithSHA1 || cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		issues = append(issues, "Certificado usa algoritmo de firma SHA1 (obsoleto)")
		result.Severity = "High"
	}

	// 4. Detalles Técnicos para el Informe
	result.Details = append(result.Details, fmt.Sprintf("🔐 Protocolo: %s", tlsVersion))
	result.Details = append(result.Details, fmt.Sprintf("🔑 Cifrado: %s", cipherSuite))
	result.Details = append(result.Details, fmt.Sprintf("📜 Certificado: %s (Emitido por: %s)", cert.Subject.CommonName, cert.Issuer.CommonName))
	result.Details = append(result.Details, fmt.Sprintf("📅 Validez: %s hasta %s", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02")))

	if len(cert.DNSNames) > 0 {
		result.Details = append(result.Details, fmt.Sprintf("🌐 Dominios alternativos (SAN): %s", strings.Join(cert.DNSNames, ", ")))
	}

	// Compilar resultado final
	if len(issues) > 0 {
		result.Status = "Failed"
		result.Description = "Se detectaron problemas de seguridad críticos o altos en SSL/TLS"
		for _, issue := range issues {
			result.Details = append(result.Details, "  ❌ "+issue)
		}
	} else if len(warnings) > 0 {
		result.Status = "Warning"
		result.Description = "La configuración SSL/TLS es segura pero con advertencias de mejores prácticas"
		for _, warning := range warnings {
			result.Details = append(result.Details, "  ⚠️ "+warning)
		}
	} else {
		result.Description = "Configuración SSL/TLS óptima detectada"
	}

	return result
}
