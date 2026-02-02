package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const (
	RepoOwner = "kriollo"
	RepoName  = "versaSecurityTest"
	BaseURL   = "https://api.github.com/repos"
)

// GithubRelease representa la estructura simplificada de un release en GitHub
type GithubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
	PublishedAt string `json:"published_at"`
}

// CheckForUpdates verifica si hay una nueva versión disponible en GitHub
func CheckForUpdates(currentVersion string) error {
	fmt.Printf("🔍 Buscando actualizaciones en: %s/%s...\n", RepoOwner, RepoName)

	url := fmt.Sprintf("%s/%s/%s/releases/latest", BaseURL, RepoOwner, RepoName)
	resp, err := http.Get(url)
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

	// Limpiar 'v' si existe para comparar
	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(currentVersion, "v")

	if latest == current {
		fmt.Printf("✨ ¡Ya tienes la última versión instalada! (%s)\n", currentVersion)
		return nil
	}

	fmt.Printf("🚀 ¡Nueva versión disponible: %s! (Versión actual: %s)\n", release.TagName, currentVersion)
	fmt.Printf("📝 Notas del release:\n%s\n", strings.Split(release.Body, "\n")[0])
	fmt.Printf("🔗 Enlace: %s\n\n", release.HTMLURL)

	// Detectar si estamos en un repo git o si es un binario
	if isGitRepo() {
		fmt.Println("🚀 Detectado entorno de desarrollo ( Git).")
		fmt.Println("Para actualizar, ejecuta: git pull && go build -o versaSecurityTest.exe")

		var confirm string
		fmt.Print("¿Quieres intentar actualizar vía git pull ahora? (s/n): ")
		fmt.Scanln(&confirm)

		if strings.ToLower(confirm) == "s" {
			return runGitUpdate()
		}
	} else {
		fmt.Println("📦 Puedes descargar el nuevo binario desde la página de releases de GitHub.")
		fmt.Println("Próximamente: Actualización automática del binario.")
	}

	return nil
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
	var buildCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		buildCmd = exec.Command("go", "build", "-o", "versaSecurityTest.exe")
	} else {
		buildCmd = exec.Command("go", "build", "-o", "versaSecurityTest")
	}

	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("error al recompilar: %v", err)
	}

	fmt.Println("✨ ¡Aplicación actualizada y compilada correctamente!")
	fmt.Println("Por favor, reinicie la aplicación.")
	return nil
}
