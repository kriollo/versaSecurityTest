package tests

import (
	"net"
	"net/url"
	"strings"
)

// sameRequestPath compara rutas HTTP ignorando la barra final.
func sameRequestPath(requested, final string) bool {
	normalize := func(p string) string {
		p = strings.TrimSuffix(p, "/")
		if p == "" {
			return "/"
		}
		return p
	}
	return normalize(requested) == normalize(final)
}

// IsLocalTarget indica si el objetivo es localhost/loopback. En estos casos
// las comprobaciones de transporte (HTTPS, HSTS, cookies Secure) no aportan
// señal real y generan falsos positivos en entornos de desarrollo.
func IsLocalTarget(targetURL string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	host := u.Hostname()
	if host == "" {
		return false
	}

	hostLower := strings.ToLower(host)
	if hostLower == "localhost" || strings.HasSuffix(hostLower, ".localhost") {
		return true
	}

	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}

	return false
}
