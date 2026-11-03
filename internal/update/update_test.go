package update

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFindAssetEligeElBinarioDeEsteSistema(t *testing.T) {
	assets := []ReleaseAsset{
		{Name: "versaSecurityTest-linux-amd64"},
		{Name: "versaSecurityTest-linux-arm64"},
		{Name: "versaSecurityTest-windows-amd64.exe"},
		{Name: "versaSecurityTest-darwin-arm64"},
	}
	got := findAsset(assets)
	if got == nil {
		t.Fatalf("no encontró binario para %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	want := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	if !strings.Contains(got.Name, want) {
		t.Fatalf("eligió %q, no coincide con %q", got.Name, want)
	}
	// En Windows debe terminar en .exe; en el resto, no
	if runtime.GOOS == "windows" && filepath.Ext(got.Name) != ".exe" {
		t.Fatalf("en Windows debe ser .exe: %q", got.Name)
	}
}

func TestFindAssetSinCoincidenciaDevuelveNil(t *testing.T) {
	if findAsset([]ReleaseAsset{{Name: "versaSecurityTest-plan9-mips"}}) != nil {
		t.Fatal("no debería coincidir con un sistema ajeno")
	}
}

func TestDownloadYReemplazoDelEjecutable(t *testing.T) {
	const nuevo = "BINARIO-NUEVO-v2"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("la petición debe llevar User-Agent (GitHub lo exige)")
		}
		w.Write([]byte(nuevo))
	}))
	defer srv.Close()

	dir := t.TempDir()
	self := filepath.Join(dir, "versaSecurityTest")
	if err := os.WriteFile(self, []byte("BINARIO-VIEJO-v1"), 0o755); err != nil {
		t.Fatal(err)
	}

	tmp := self + ".new"
	if err := download(srv.URL, tmp); err != nil {
		t.Fatal(err)
	}
	if err := replaceExecutable(tmp, self); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(self)
	if string(got) != nuevo {
		t.Fatalf("el ejecutable no se reemplazó: %q", got)
	}
	if _, err := os.Stat(self + ".new"); !os.IsNotExist(err) {
		t.Error("el archivo .new temporal debería haberse movido")
	}
	if _, err := os.Stat(self + ".old"); !os.IsNotExist(err) {
		t.Error("el .old debería haberse borrado")
	}
}
