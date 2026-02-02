package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// ProgressUpdateMsg es un mensaje que actualiza el progreso de un test específico
type ProgressUpdateMsg struct {
	TestIndex int
	Status    string // "running", "completed", "failed"
	Message   string
	Duration  time.Duration
}

// ProgressTickMsg es el mensaje para el tick del progreso
type ProgressTickMsg struct {
	Time time.Time
}

// FinishingTickMsg es el mensaje para el tick del spinner de finalización
type FinishingTickMsg struct {
	Time time.Time
}

// startScanWithProgress inicia el escaneo con actualizaciones de progreso en tiempo real
func (m Model) startScanWithProgress() tea.Cmd {
	return tea.Batch(
		// Solo necesitamos el ticker, la lógica ya está en el Update
		m.tickProgress(),
	)
}

// StartProgressUpdater inicia el actualizador de progreso
func (m Model) StartProgressUpdater() tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		// Obtener Tests seleccionados
		selectedTests := []TestItem{}
		for _, test := range m.Tests {
			if test.Selected {
				selectedTests = append(selectedTests, test)
			}
		}

		if len(selectedTests) == 0 {
			return ScanCompleteMsg{Result: nil, error: nil}
		}

		// Ejecutar Tests de manera síncrona pero enviando actualizaciones
		for i := range selectedTests {
			// Simular inicio del test
			time.Sleep(time.Duration(200+i*50) * time.Millisecond)

			// Simular ejecución
			testDuration := time.Duration(800+i*100) * time.Millisecond
			time.Sleep(testDuration)

			// El test se completa aquí
		}

		// Todos los Tests han terminado
		return ScanCompleteMsg{
			Result: nil, // Se llenará con resultados reales
			error:  nil,
		}
	})
}

// initializeProgress inicializa la estructura de progreso
func (m Model) initializeProgress() Model {
	// Crear lista inicial de Tests con estado "pending"
	var testDetails []TestProgress
	for _, test := range m.Tests {
		if test.Selected {
			testDetails = append(testDetails, TestProgress{
				Name:      test.Name,
				Status:    "pending",
				StartTime: time.Now(),
				Message:   "Esperando ejecución...",
			})
		}
	}

	m.ScanProgress = ScanProgress{
		Total:       len(testDetails),
		Completed:   0,
		StartTime:   time.Now(),
		TestDetails: testDetails,
		Duration:    0,
	}

	return m
}

// tickProgress envía ticks regulares para actualizar la UI
func (m Model) tickProgress() tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(t time.Time) tea.Msg {
		return ProgressTickMsg{Time: t}
	})
}

// tickFinishing envía ticks para el spinner de finalización
func (m Model) tickFinishing() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return FinishingTickMsg{Time: t}
	})
}
