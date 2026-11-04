package version

import (
	"runtime/debug"
	"strings"
)

// Version se puede inyectar en tiempo de compilación:
//
//	go build -ldflags "-X github.com/versaSecurityTest/internal/version.Version=2.2.0"
var Version = ""

// Get devuelve la versión efectiva: ldflags > módulo instalado > revisión VCS > "dev".
func Get() string {
	if v := strings.TrimSpace(Version); v != "" {
		return normalize(v)
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return normalize(v)
		}
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				rev := s.Value
				if len(rev) > 7 {
					rev = rev[:7]
				}
				return "dev-" + rev
			}
		}
	}
	return "dev"
}

func normalize(v string) string {
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return "dev"
	}
	return v
}
