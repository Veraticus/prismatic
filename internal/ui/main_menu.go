package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// MainMenu represents the main menu page.
type MainMenu struct {
	choices []string
	cursor  int
	width   int
	height  int
}

// NewMainMenu creates a new main menu.
func NewMainMenu() *MainMenu {
	return &MainMenu{
		choices: []string{
			"New Scan",
			"Scan History",
			"Results Browser",
			"Settings",
			"Quit",
		},
		cursor: 0,
	}
}

// Init initializes the main menu.
func (m *MainMenu) Init() tea.Cmd {
	return nil
}

// Update handles main menu updates.
func (m *MainMenu) Update(msg tea.Msg) (*MainMenu, tea.Cmd) {
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.String() {
		// Vim-style navigation
		case "k", "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "j", "down":
			if m.cursor < len(m.choices)-1 {
				m.cursor++
			}
		case "g":
			m.cursor = 0
		case "G":
			m.cursor = len(m.choices) - 1
		// Selection
		case "enter", " ":
			cmd := m.handleSelection()
			return m, cmd
		// Quick keys
		case "n":
			m.cursor = 0
			cmd := m.handleSelection()
			return m, cmd
		case "h":
			m.cursor = 1
			cmd := m.handleSelection()
			return m, cmd
		case "q":
			return m, tea.Quit
		}
	}
	return m, nil
}

// View renders the main menu.
func (m *MainMenu) View() string {
	var b strings.Builder

	// Title with prismatic style
	title := TitleStyle.Render("🔍 Prismatic Security Scanner")
	b.WriteString(lipgloss.PlaceHorizontal(m.width, lipgloss.Center, title))
	b.WriteString("\n\n")

	// Menu items
	menuStyle := lipgloss.NewStyle().
		Align(lipgloss.Center).
		Width(m.width)

	for i, choice := range m.choices {
		cursor := "  "
		style := NormalItemStyle

		if m.cursor == i {
			cursor = "▸ "
			style = SelectedItemStyle
		}

		// Add keyboard shortcuts
		shortcut := ""
		switch i {
		case 0:
			shortcut = "[n] "
		case 1:
			shortcut = "[h] "
		case 4:
			shortcut = "[q] "
		default:
			shortcut = "    "
		}

		item := fmt.Sprintf("%s%s%s", cursor, shortcut, choice)
		b.WriteString(menuStyle.Render(style.Render(item)))
		b.WriteString("\n")
	}

	// Help text
	b.WriteString("\n\n")
	help := HelpStyle.Render("Navigate: ↑/↓ or j/k • Select: Enter • Quick: n/h/q")
	b.WriteString(lipgloss.PlaceHorizontal(m.width, lipgloss.Center, help))

	// Center everything vertically
	content := b.String()
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
}

// SetSize updates the menu dimensions.
func (m *MainMenu) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// handleSelection processes menu selections.
func (m *MainMenu) handleSelection() tea.Cmd {
	switch m.cursor {
	case 0: // New Scan
		return func() tea.Msg {
			return NavigateToPageMsg{Page: ScannerConfigPage}
		}
	case 1: // Scan History
		return func() tea.Msg {
			return NavigateToPageMsg{Page: ScanHistoryPage}
		}
	case 2: // Results Browser
		return func() tea.Msg {
			return NavigateToPageMsg{Page: ResultsBrowserPage}
		}
	case 3: // Reports
		// TODO: Implement reports browser page
		return nil
	case 4: // Settings
		// TODO: Implement settings page
		return nil
	case 5: // Quit
		return tea.Quit
	}
	return nil
}
