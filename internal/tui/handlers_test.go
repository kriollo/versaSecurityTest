package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// Regresión: escribir "v" en el campo de URL debe agregar la letra, no activar el verbose global.
func TestEscribirVEnURLNoLaComeElHotkey(t *testing.T) {
	m := Model{State: StateURL, Width: 80, Height: 24}
	for _, r := range "https://victima.cl" {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = updated.(Model)
	}
	if m.URL != "https://victima.cl" {
		t.Fatalf("la URL perdió caracteres (¿hotkey comiéndose la 'v'?): %q", m.URL)
	}
	if m.Verbose {
		t.Fatalf("escribir en la URL no debe activar el modo verbose")
	}
}

func TestIsValidURLChar(t *testing.T) {
	for _, c := range []string{"v", "V", "%", "+", "#", "~", ",", ":", "/", "?"} {
		if !IsValidURLChar(c) {
			t.Errorf("%q debería ser válido en una URL", c)
		}
	}
	for _, c := range []string{" ", "\t", "\n"} {
		if IsValidURLChar(c) {
			t.Errorf("%q no debería permitirse", c)
		}
	}
}
