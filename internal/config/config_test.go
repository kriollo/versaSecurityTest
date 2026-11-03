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
