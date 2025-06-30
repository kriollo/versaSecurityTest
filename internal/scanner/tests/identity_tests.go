package tests

import (
	"fmt"

	"github.com/versaSecurityTest/internal/config"
)

// IdentityManagementTest - Categoría IDNT (IDNT-01 a IDNT-05)
type IdentityManagementTest struct{}

func (t *IdentityManagementTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "IDNT-01: Identity Management Testing",
		Description: "Detección de mecanismos de gestión de identidad",
	}

	var details []string
	var evidence []Evidence

	// IDNT-01: Detectar formularios de registro
	registrationEndpoints := []string{
		"/register", "/signup", "/registration", "/create-account",
		"/register.php", "/signup.php", "/join", "/new-user",
		"/api/register", "/api/signup", "/auth/register",
	}

	for _, endpoint := range registrationEndpoints {
		resp, err := client.Get(targetURL + endpoint)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			details = append(details, fmt.Sprintf("Endpoint de registro encontrado: %s", endpoint))
			evidence = append(evidence, Evidence{
				Type:        "Registration Endpoint",
				URL:         targetURL + endpoint,
				StatusCode:  resp.StatusCode,
				Description: fmt.Sprintf("Formulario de registro accesible: %s", endpoint),
				Severity:    "Info",
			})
		}
	}

	// IDNT-02: Detectar formularios de login
	loginEndpoints := []string{
		"/login", "/signin", "/auth", "/authenticate",
		"/login.php", "/signin.php", "/admin/login",
		"/api/login", "/api/auth", "/oauth/authorize",
	}

	for _, endpoint := range loginEndpoints {
		resp, err := client.Get(targetURL + endpoint)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			details = append(details, fmt.Sprintf("Endpoint de login encontrado: %s", endpoint))
			evidence = append(evidence, Evidence{
				Type:        "Login Endpoint",
				URL:         targetURL + endpoint,
				StatusCode:  resp.StatusCode,
				Description: fmt.Sprintf("Formulario de login accesible: %s", endpoint),
				Severity:    "Info",
			})
		}
	}

	// IDNT-03: Detectar endpoints de recuperación de contraseña
	recoveryEndpoints := []string{
		"/forgot-password", "/reset-password", "/password-reset",
		"/recover", "/forgot", "/reset", "/password-recovery",
		"/api/forgot-password", "/api/password-reset",
	}

	for _, endpoint := range recoveryEndpoints {
		resp, err := client.Get(targetURL + endpoint)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			details = append(details, fmt.Sprintf("Endpoint de recuperación encontrado: %s", endpoint))
			evidence = append(evidence, Evidence{
				Type:        "Password Recovery",
				URL:         targetURL + endpoint,
				StatusCode:  resp.StatusCode,
				Description: fmt.Sprintf("Sistema de recuperación de contraseña: %s", endpoint),
				Severity:    "Info",
			})
		}
	}

	// IDNT-04: Detectar perfiles de usuario
	profileEndpoints := []string{
		"/profile", "/user", "/account", "/dashboard",
		"/my-account", "/settings", "/preferences",
		"/api/profile", "/api/user", "/api/account",
	}

	for _, endpoint := range profileEndpoints {
		resp, err := client.Get(targetURL + endpoint)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			details = append(details, fmt.Sprintf("Endpoint de perfil encontrado: %s (Status: %d)", endpoint, resp.StatusCode))

			severity := "Info"
			if resp.StatusCode == 200 {
				severity = "Medium" // Acceso sin autenticación
			}

			evidence = append(evidence, Evidence{
				Type:        "User Profile",
				URL:         targetURL + endpoint,
				StatusCode:  resp.StatusCode,
				Description: fmt.Sprintf("Endpoint de perfil de usuario: %s", endpoint),
				Severity:    severity,
			})
		}
	}

	result.Details = details
	result.Evidence = evidence

	if len(evidence) == 0 {
		result.Status = "Passed"
		result.Severity = "Info"
		result.Description = "No se encontraron mecanismos de gestión de identidad"
	} else {
		result.Status = "Passed"
		result.Severity = "Info"
		result.Description = fmt.Sprintf("Se identificaron %d mecanismos de gestión de identidad", len(evidence))
	}

	return result
}

// UserEnumerationTest - IDNT-05: User Enumeration
type UserEnumerationTest struct{}

func (t *UserEnumerationTest) Run(targetURL string, client HTTPClient, payloads *config.PayloadConfig) TestResult {
	result := TestResult{
		TestName:    "IDNT-05: User Enumeration Testing",
		Description: "Pruebas de enumeración de usuarios",
	}

	var details []string
	var evidence []Evidence

	// Probar enumeración de usuarios en endpoints comunes
	testUsers := []string{"admin", "administrator", "test", "user", "guest", "demo"}
	userEndpoints := []string{
		"/user/", "/users/", "/profile/", "/api/user/", "/api/users/",
	}

	for _, endpoint := range userEndpoints {
		for _, user := range testUsers {
			testURL := targetURL + endpoint + user
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			details = append(details, fmt.Sprintf("Probando usuario %s en %s (Status: %d)", user, endpoint, resp.StatusCode))

			// Si retorna 200, podría existir el usuario
			if resp.StatusCode == 200 {
				evidence = append(evidence, Evidence{
					Type:        "User Enumeration",
					URL:         testURL,
					StatusCode:  resp.StatusCode,
					Description: fmt.Sprintf("Posible usuario válido encontrado: %s", user),
					Severity:    "Medium",
				})
			}
		}
	}

	// Probar enumeración en formularios de login con errores diferenciados
	loginURL := targetURL + "/login"
	testCases := []struct {
		username string
		password string
		desc     string
	}{
		{"nonexistentuser12345", "wrongpassword", "usuario inexistente"},
		{"admin", "wrongpassword", "usuario común con contraseña incorrecta"},
	}

	for _, testCase := range testCases {
		// Simular POST request (simplificado)
		details = append(details, fmt.Sprintf("Probando login con %s", testCase.desc))

		resp, err := client.Get(fmt.Sprintf("%s?username=%s&password=%s", loginURL, testCase.username, testCase.password))
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Análisis básico de respuesta (en una implementación real sería más sofisticado)
		if resp.StatusCode == 200 {
			details = append(details, fmt.Sprintf("Respuesta recibida para %s", testCase.username))
		}
	}

	result.Details = details
	result.Evidence = evidence

	if len(evidence) == 0 {
		result.Status = "Passed"
		result.Severity = "Info"
	} else {
		result.Status = "Failed"
		result.Severity = "Medium"
	}

	return result
}
