package tests

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/versaSecurityTest/internal/config"
)

// PortScanTest - Categoría NETW
type PortScanTest struct {
	// Puertos comunes a escanear
	CommonPorts []int
}

// ServiceInfo contiene información sobre un servicio detectado
type ServiceInfo struct {
	Port    int
	Service string
	Detail  string
}

// Run ejecuta un escaneo de puertos sobre el objetivo
func (t *PortScanTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "NETW-01: Network Port Scan",
		Status:      "Passed",
		Description: "Escaneo de puertos abiertos y servicios expuestos",
		Severity:    "Info",
		Details:     []string{},
		Evidence:    []Evidence{},
	}

	// Extraer el host (dominio o IP) de la URL
	host := extractHost(targetURL)
	if host == "" {
		result.Status = "Failed"
		result.Description = "No se pudo extraer el host de la URL"
		return result
	}

	// Puertos prioritarios a escanear (OWASP & comunes)
	if len(t.CommonPorts) == 0 {
		t.CommonPorts = []int{
			21,    // FTP
			22,    // SSH
			23,    // Telnet (Inseguro)
			25,    // SMTP
			53,    // DNS
			80,    // HTTP
			110,   // POP3
			143,   // IMAP
			443,   // HTTPS
			445,   // SMB
			1433,  // MSSQL
			2049,  // NFS
			3306,  // MySQL
			3389,  // RDP
			5432,  // PostgreSQL
			6379,  // Redis
			8080,  // HTTP Alt
			8443,  // HTTPS Alt
			27017, // MongoDB
		}
	}

	var openPorts []ServiceInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Escaneo concurrente
	limit := make(chan struct{}, 50) // Límite de 50 goroutines simultáneas

	for _, port := range t.CommonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()

			address := net.JoinHostPort(host, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err == nil {
				conn.Close()

				serviceName := getServiceName(p)
				mu.Lock()
				openPorts = append(openPorts, ServiceInfo{
					Port:    p,
					Service: serviceName,
				})
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()

	// Procesar resultados
	if len(openPorts) > 0 {
		result.Description = fmt.Sprintf("Se detectaron %d puertos abiertos", len(openPorts))

		for _, info := range openPorts {
			severity := "Info"
			detail := fmt.Sprintf("Puerto %d (%s) abierto", info.Port, info.Service)

			// Alertar sobre servicios inseguros
			if info.Service == "Telnet" || info.Service == "FTP" || info.Service == "SMB" {
				severity = "Medium"
				detail += " - ¡Servicio potencialmente inseguro!"
				result.Status = "Warning"
				if result.Severity == "Info" {
					result.Severity = "Medium"
				}
			}

			result.Details = append(result.Details, detail)
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "Open Port",
				URL:         host,
				Description: detail,
				Severity:    severity,
				StatusCode:  info.Port,
			})
		}
	} else {
		result.Details = append(result.Details, "No se detectaron puertos comunes abiertos fuera de los estándares web.")
	}

	return result
}

// extractHost limpia la URL para obtener solo el host
func extractHost(targetURL string) string {
	host := targetURL
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")

	// Eliminar path si existe
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	// Eliminar puerto si existe en la URL original
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	return host
}

// getServiceName retorna un nombre amigable para puertos comunes
func getServiceName(port int) string {
	services := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		445:   "SMB",
		1433:  "MSSQL",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		6379:  "Redis",
		8080:  "HTTP Proxy/Alt",
		8443:  "HTTPS Alt",
		27017: "MongoDB",
	}

	if name, ok := services[port]; ok {
		return name
	}
	return "Unknown"
}
