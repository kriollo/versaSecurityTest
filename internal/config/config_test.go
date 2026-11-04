package config

import "testing"

// Cada test de la lista debe tener su caso en IsTestEnabled/SetTestEnabled; si no, la TUI lo muestra
// pero nunca se ejecuta. Este test lo garantiza para todos, incluido known_vulns.
func TestCadaTestDisponibleSePuedeActivar(t *testing.T) {
	c := &Config{}
	available := GetAvailableTests()
	if len(available) == 0 {
		t.Fatal("no hay tests disponibles")
	}

	var hasKnownVulns bool
	for _, def := range available {
		if def.ID == "known_vulns" {
			hasKnownVulns = true
		}
		c.SetTestEnabled(def.ID, true)
		if !c.IsTestEnabled(def.ID) {
			t.Errorf("%q no se activa con SetTestEnabled/IsTestEnabled (falta su case en el switch)", def.ID)
		}
		c.SetTestEnabled(def.ID, false)
		if c.IsTestEnabled(def.ID) {
			t.Errorf("%q no se desactiva", def.ID)
		}
	}

	if !hasKnownVulns {
		t.Error("known_vulns no está en la lista de tests disponibles (no aparecería en la TUI)")
	}
}

// El conteo de tests por perfil debe coincidir con los que realmente se ejecutan (lista única +
// IsTestEnabled), no con una lista a mano. Regresión: antes omitía 6 tests y el número salía bajo.
func TestConteoDeTestsPorPerfilEsCorrecto(t *testing.T) {
	c := DefaultConfig()
	avail := GetAvailableTests()

	for _, id := range []string{"basic", "standard", "advanced"} {
		prof, err := c.GetProfileInfo(id)
		if err != nil {
			t.Fatalf("perfil %s: %v", id, err)
		}
		pc := &Config{Tests: prof.Tests}
		manual := 0
		for _, def := range avail {
			if pc.IsTestEnabled(def.ID) {
				manual++
			}
		}
		got := c.CountEnabledTests(id)
		if got != manual {
			t.Errorf("perfil %s: CountEnabledTests=%d pero los tests habilitados son %d", id, got, manual)
		}
		t.Logf("perfil %s: %d tests", id, got)
	}

	// El perfil avanzado habilita todo → debe contar todos los tests disponibles.
	if got := c.CountEnabledTests("advanced"); got != len(avail) {
		t.Errorf("advanced debería habilitar los %d tests disponibles, contó %d", len(avail), got)
	}
}
