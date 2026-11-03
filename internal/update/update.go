package update

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	RepoOwner = "kriollo"
	RepoName  = "versaSecurityTest"
	BaseURL   = "https://api.github.com/repos"
)

// GithubRelease representa la estructura simplificada de un release en GitHub
type GithubRelease struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	HTMLURL     string         `json:"html_url"`
	Body        string         `json:"body"`
	PublishedAt string         `json:"published_at"`
	Assets      []ReleaseAsset `json:"assets"`
}

// ReleaseAsset es un binario adjunto al release.
type ReleaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// httpClient con timeout y User-Agent: la API de GitHub rechaza peticiones sin User-Agent (403).
var httpClient = &http.Client{Timeout: 60 * time.Second}

func githubGet(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", RepoName+"-self-update")
	return httpClient.Do(req)
}

// CheckForUpdates verifica si hay una nueva versión y ofrece actualizar (git o binario, según el entorno).
func CheckForUpdates(currentVersion string) error {
	fmt.Printf("🔍 Buscando actualizaciones en: %s/%s...\n", RepoOwner, RepoName)

	url := fmt.Sprintf("%s/%s/%s/releases/latest", BaseURL, RepoOwner, RepoName)
	resp, err := githubGet(url)
	if err != nil {
		return fmt.Errorf("error al conectar con GitHub: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("no se pudo obtener información de la versión (status: %d)", resp.StatusCode)
	}

	var release GithubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("error al procesar respuesta de GitHub: %v", err)
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(currentVersion, "v")
	if latest == current {
		fmt.Printf("✨ ¡Ya tienes la última versión instalada! (%s)\n", currentVersion)
		return nil
	}

	fmt.Printf("🚀 ¡Nueva versión disponible: %s! (Versión actual: %s)\n", release.TagName, currentVersion)
	if release.Body != "" {
		fmt.Printf("📝 Notas del release:\n%s\n", strings.Split(release.Body, "\n")[0])
	}
	fmt.Printf("🔗 Enlace: %s\n\n", release.HTMLURL)

	// En un clon de desarrollo se actualiza con git; como binario instalado, se reemplaza el ejecutable.
	if isGitRepo() {
		fmt.Println("🚀 Detectado entorno de desarrollo (Git).")
		if confirm("¿Actualizar vía 'git pull' y recompilar ahora? (s/n): ") {
			return runGitUpdate()
		}
		return nil
	}

	if confirm("¿Descargar e instalar la nueva versión ahora? (s/n): ") {
		return runBinaryUpdate(&release)
	}
	fmt.Printf("📦 También puedes descargarla a mano desde: %s\n", release.HTMLURL)
	return nil
}

// runBinaryUpdate descarga el binario del release para este sistema y reemplaza el ejecutable actual.
func runBinaryUpdate(release *GithubRelease) error {
	asset := findAsset(release.Assets)
	if asset == nil {
		return fmt.Errorf("el release no trae un binario para %s/%s; descárgalo a mano desde %s",
			runtime.GOOS, runtime.GOARCH, release.HTMLURL)
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("no se pudo ubicar el ejecutable actual: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}

	fmt.Printf("⬇️  Descargando %s (%.1f MB)...\n", asset.Name, float64(asset.Size)/(1<<20))
	// El archivo nuevo se escribe junto al ejecutable: el reemplazo queda en el mismo disco (rename atómico)
	tmp := self + ".new"
	if err := download(asset.URL, tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}

	if err := replaceExecutable(tmp, self); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("no se pudo reemplazar el ejecutable: %v", err)
	}

	fmt.Printf("✨ ¡Actualizado a %s! Vuelve a ejecutar la aplicación.\n", release.TagName)
	return nil
}

// findAsset elige el binario del release cuyo nombre coincide con este sistema
// (versaSecurityTest-<os>-<arch>[.exe]).
func findAsset(assets []ReleaseAsset) *ReleaseAsset {
	want := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	for i := range assets {
		name := strings.ToLower(assets[i].Name)
		if strings.Contains(name, want) && strings.HasSuffix(name, suffix) {
			return &assets[i]
		}
	}
	return nil
}

func download(url, dest string) error {
	resp, err := githubGet(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("descarga falló (status: %d)", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, resp.Body)
	closeErr := out.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if n == 0 {
		return fmt.Errorf("la descarga llegó vacía")
	}
	return nil
}

// replaceExecutable deja el binario nuevo en el lugar del actual. Un .exe en uso (Windows) no se puede
// sobrescribir, pero sí renombrar: se corre el actual a .old y se pone el nuevo en su sitio.
func replaceExecutable(newPath, dest string) error {
	old := dest + ".old"
	_ = os.Remove(old)
	if err := os.Rename(dest, old); err != nil {
		return err
	}
	if err := os.Rename(newPath, dest); err != nil {
		_ = os.Rename(old, dest) // deshacer: dejar el original en su lugar
		return err
	}
	// En Windows el .old sigue en uso hasta cerrar el proceso; si no se puede borrar ahora, no importa
	_ = os.Remove(old)
	return nil
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	var answer string
	fmt.Scanln(&answer)
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "s" || answer == "si" || answer == "y" || answer == "yes"
}

func isGitRepo() bool {
	_, err := os.Stat(".git")
	return err == nil
}

func runGitUpdate() error {
	fmt.Println("🔄 Ejecutando 'git pull'...")
	cmd := exec.Command("git", "pull")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error al ejecutar git pull: %v", err)
	}

	fmt.Println("🛠️  Recompilando aplicación...")
	out := "versaSecurityTest"
	if runtime.GOOS == "windows" {
		out = "versaSecurityTest.exe"
	}
	buildCmd := exec.Command("go", "build", "-o", out, ".")
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("error al recompilar: %v", err)
	}

	fmt.Println("✨ ¡Aplicación actualizada y compilada correctamente! Reinicia la aplicación.")
	return nil
}
