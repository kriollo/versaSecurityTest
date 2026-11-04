package version

import (
	"regexp"
	"runtime/debug"
	"strings"
)

// Version se puede inyectar en tiempo de compilación:
//
//	go build -ldflags "-X github.com/versaSecurityTest/internal/version.Version=2.2.0"
var Version = ""

// pseudoVersionRe coincide con versiones generadas por `go build` a partir del
// estado de VCS, por ejemplo v0.0.0-20261104024103-c74603fef2de. No son
// versiones de release y en la UI se muestran como dev-<commit>.
var pseudoVersionRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+.*[.-]\d{14}-[0-9a-f]{7,}$`)

// Get devuelve la versión efectiva: ldflags > módulo instalado > revisión VCS > "dev".
func Get() string {
	if v := strings.TrimSpace(Version); v != "" {
		return normalize(v)
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			if isPseudoVersion(v) {
				return devFromRevision(info)
			}
			return normalize(v)
		}
		return devFromRevision(info)
	}
	return "dev"
}

// Label devuelve la versión lista para mostrar en la UI, con prefijo "v"
// solo cuando es una versión numérica de release.
func Label() string {
	v := Get()
	if v == "dev" || strings.HasPrefix(v, "dev-") {
		return v
	}
	return "v" + v
}

func isPseudoVersion(v string) bool {
	// `go build` añade +dirty cuando el árbol de trabajo tiene cambios.
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	return pseudoVersionRe.MatchString(v)
}

func devFromRevision(info *debug.BuildInfo) string {
	rev := ""
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			rev = s.Value
			break
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	return "dev-" + rev
}

func normalize(v string) string {
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return "dev"
	}
	return v
}
