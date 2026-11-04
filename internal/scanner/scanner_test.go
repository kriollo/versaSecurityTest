package scanner

import (
	"testing"

	"github.com/versaSecurityTest/internal/config"
	"github.com/versaSecurityTest/internal/scanner/tests"
)

func scoreOf(trs []tests.TestResult) SecurityScore {
	ws := &WebScanner{config: &config.Config{}, silent: true}
	r := &ScanResult{TestResults: trs, TestsExecuted: len(trs)}
	return ws.calculateSecurityScore(r)
}

func tr(status, sev string) tests.TestResult {
	return tests.TestResult{Status: status, Severity: sev}
}

// Un hallazgo crítico DOMINA la nota: aunque pasen muchos tests, nunca puede salir "Bajo".
func TestScoreCriticoNuncaEsBajo(t *testing.T) {
	trs := []tests.TestResult{tr("Failed", "Critical")}
	for i := 0; i < 28; i++ {
		trs = append(trs, tr("Passed", "None"))
	}
	s := scoreOf(trs)
	if s.Value >= 4 || s.Risk != "Crítico" {
		t.Fatalf("con un crítico debe ser <4 y 'Crítico', fue %.2f/%s", s.Value, s.Risk)
	}
}

// El tope por severidad ubica la nota en la banda correcta según el peor hallazgo.
func TestScoreTopePorSeveridad(t *testing.T) {
	base := func(sev string) []tests.TestResult {
		trs := []tests.TestResult{tr("Failed", sev)}
		for i := 0; i < 19; i++ {
			trs = append(trs, tr("Passed", "None"))
		}
		return trs
	}
	cases := map[string][2]float64{ // sev -> [maxEsperado, techo de banda]
		"High":   {5.9, 4.0},
		"Medium": {7.9, 6.0},
		"Low":    {9.4, 0},
	}
	for sev, want := range cases {
		s := scoreOf(base(sev))
		if s.Value > want[0]+0.001 {
			t.Errorf("%s: score %.2f supera el tope %.1f", sev, s.Value, want[0])
		}
	}
	// High debe quedar en banda "Alto" (4-5.9)
	if s := scoreOf(base("High")); s.Risk != "Alto" {
		t.Errorf("un High debería ser 'Alto', fue %s (%.2f)", s.Risk, s.Value)
	}
}

// Todo limpio = nota alta y "Bajo".
func TestScoreTodoLimpioEsBajo(t *testing.T) {
	var trs []tests.TestResult
	for i := 0; i < 20; i++ {
		trs = append(trs, tr("Passed", "None"))
	}
	s := scoreOf(trs)
	if s.Value < 8 || s.Risk != "Bajo" {
		t.Fatalf("todo limpio debería ser >=8 'Bajo', fue %.2f/%s", s.Value, s.Risk)
	}
}
