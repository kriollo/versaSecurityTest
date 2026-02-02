package tui

import "github.com/charmbracelet/lipgloss"

// Palette definition
var (
	ColorPrimary   = lipgloss.Color("#3498db") // Blue
	ColorSecondary = lipgloss.Color("#2c3e50") // Dark Gray Blue
	ColorSuccess   = lipgloss.Color("#2ecc71") // Green
	ColorWarning   = lipgloss.Color("#f1c40f") // Yellow
	ColorDanger    = lipgloss.Color("#e74c3c") // Red
	ColorNeutral   = lipgloss.Color("#ecf0f1") // Light Gray
	ColorFocus     = lipgloss.Color("#9b59b6") // Purple
	ColorBoxBg     = lipgloss.Color("#1a1a1a") // Very Dark Gray
)

var (
	TitleStyle = lipgloss.NewStyle().
			Foreground(ColorNeutral).
			Background(ColorPrimary).
			Padding(0, 2).
			Bold(true).
			MarginBottom(1)

	HeaderStyle = lipgloss.NewStyle().
			Foreground(ColorPrimary).
			Bold(true).
			MarginBottom(1)

	FocusedStyle = lipgloss.NewStyle().
			Foreground(ColorNeutral).
			Background(ColorFocus).
			Padding(0, 1).
			Bold(true)

	SelectedStyle = lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)

	NormalStyle = lipgloss.NewStyle().
			Foreground(ColorNeutral)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(ColorDanger).
			Bold(true)

	WarningStyle = lipgloss.NewStyle().
			Foreground(ColorWarning).
			Bold(true)

	SuccessStyle = lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)

	ModalStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorPrimary).
			Padding(1, 2).
			Background(ColorBoxBg)

	CardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorSecondary).
			Padding(0, 1).
			MarginBottom(1)

	CardFocusStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(ColorPrimary).
			Padding(0, 1).
			MarginBottom(1)

	ProgressBarStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#333333"))

	ProgressFillStyle = lipgloss.NewStyle().
				Background(ColorSuccess)
)

// Icons for better UX
const (
	IconCheck    = "✓"
	IconCircle   = "○"
	IconDiamond  = "◇"
	IconShield   = "🛡️"
	IconTarget   = "🎯"
	IconWarning  = "⚠️"
	IconCritical = "🚨"
	IconClock    = "⏱️"
	IconSearch   = "🔍"
)
