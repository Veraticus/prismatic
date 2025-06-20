// Package ui provides terminal user interface components for the scanner.
package ui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ModalType represents the type of modal dialog.
type ModalType int

const (
	// ModalTypeConfirm shows a Yes/No confirmation dialog.
	ModalTypeConfirm ModalType = iota
	// ModalTypeInput shows a text input dialog.
	ModalTypeInput
	// ModalTypeInfo shows an information dialog with OK button.
	ModalTypeInfo
	// ModalTypeError shows an error dialog with OK button.
	ModalTypeError
)

// ModalResult represents the result of a modal interaction.
type ModalResult struct {
	Input     string
	Confirmed bool
	Canceled  bool
}

// ModalClosedMsg is sent when a modal is closed.
type ModalClosedMsg struct {
	Result ModalResult
}

// Modal represents a modal dialog component.
type Modal struct {
	callback    func(ModalResult)
	validation  func(string) error
	title       string
	message     string
	placeholder string
	buttons     []string
	textInput   textinput.Model
	modalType   ModalType
	width       int
	height      int
	focusIndex  int
}

// ModalOption is a function that configures a modal.
type ModalOption func(*Modal)

// WithPlaceholder sets the placeholder text for input modals.
func WithPlaceholder(placeholder string) ModalOption {
	return func(m *Modal) {
		m.placeholder = placeholder
	}
}

// WithValidation sets the validation function for input modals.
func WithValidation(validation func(string) error) ModalOption {
	return func(m *Modal) {
		m.validation = validation
	}
}

// WithCallback sets the callback function to be called when modal closes.
func WithCallback(callback func(ModalResult)) ModalOption {
	return func(m *Modal) {
		m.callback = callback
	}
}

// NewModal creates a new modal dialog.
func NewModal(modalType ModalType, title, message string, opts ...ModalOption) *Modal {
	m := &Modal{
		modalType:  modalType,
		title:      title,
		message:    message,
		width:      60,
		height:     10,
		focusIndex: 0,
	}

	// Apply options
	for _, opt := range opts {
		opt(m)
	}

	// Set buttons based on modal type
	switch modalType {
	case ModalTypeConfirm:
		m.buttons = []string{"Yes", "No"}
		m.focusIndex = 1 // Default to No for safety
	case ModalTypeInput:
		m.buttons = []string{"OK", "Cancel"}
		// Initialize text input
		ti := textinput.New()
		ti.Placeholder = m.placeholder
		ti.Focus()
		ti.CharLimit = 256
		ti.Width = m.width - 4
		m.textInput = ti
	case ModalTypeInfo, ModalTypeError:
		m.buttons = []string{"OK"}
	}

	return m
}

// Init initializes the modal.
func (m *Modal) Init() tea.Cmd {
	if m.modalType == ModalTypeInput {
		return textinput.Blink
	}
	return nil
}

// Update handles messages for the modal.
func (m *Modal) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			// Always allow ESC to cancel
			result := ModalResult{Canceled: true}
			if m.callback != nil {
				m.callback(result)
			}
			return m, func() tea.Msg { return ModalClosedMsg{Result: result} }

		case "tab", "shift+tab":
			// Navigate between buttons
			if m.modalType != ModalTypeInput || !m.textInput.Focused() {
				if msg.String() == "tab" {
					m.focusIndex = (m.focusIndex + 1) % len(m.buttons)
				} else {
					m.focusIndex = (m.focusIndex - 1 + len(m.buttons)) % len(m.buttons)
				}
			}

		case "left", "h":
			// Navigate buttons left
			if m.modalType != ModalTypeInput || !m.textInput.Focused() {
				if m.focusIndex > 0 {
					m.focusIndex--
				}
			}

		case "right", "l":
			// Navigate buttons right
			if m.modalType != ModalTypeInput || !m.textInput.Focused() {
				if m.focusIndex < len(m.buttons)-1 {
					m.focusIndex++
				}
			}

		case "enter", " ":
			// Handle button press
			if m.modalType == ModalTypeInput && m.textInput.Focused() {
				// In input mode, Enter submits if input is valid
				if m.validation != nil {
					if err := m.validation(m.textInput.Value()); err != nil {
						// TODO: Show validation error
						return m, nil
					}
				}
				result := ModalResult{
					Input:     m.textInput.Value(),
					Confirmed: true,
				}
				if m.callback != nil {
					m.callback(result)
				}
				return m, func() tea.Msg { return ModalClosedMsg{Result: result} }
			}

			// Handle button selection
			result := m.handleButtonPress(m.focusIndex)
			if m.callback != nil {
				m.callback(result)
			}
			return m, func() tea.Msg { return ModalClosedMsg{Result: result} }
		}

	case tea.WindowSizeMsg:
		// Adjust modal size if needed
		m.width = min(msg.Width-4, 80)
		m.height = min(msg.Height-4, 20)
		if m.modalType == ModalTypeInput {
			m.textInput.Width = m.width - 4
		}
	}

	// Update text input if it's an input modal
	if m.modalType == ModalTypeInput {
		var cmd tea.Cmd
		m.textInput, cmd = m.textInput.Update(msg)
		return m, cmd
	}

	return m, nil
}

// View renders the modal.
func (m *Modal) View() string {
	// Create styles
	overlayStyle := lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("86"))

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("86")).
		Width(m.width - 2).
		Align(lipgloss.Center).
		MarginBottom(1)

	messageStyle := lipgloss.NewStyle().
		Width(m.width - 4).
		Align(lipgloss.Center).
		MarginBottom(1)

	var content strings.Builder

	// Title
	content.WriteString(titleStyle.Render(m.title))
	content.WriteString("\n")

	// Message
	if m.message != "" {
		content.WriteString(messageStyle.Render(m.message))
		content.WriteString("\n")
	}

	// Input field for input modals
	if m.modalType == ModalTypeInput {
		content.WriteString(m.textInput.View())
		content.WriteString("\n\n")
	}

	// Buttons
	content.WriteString(m.renderButtons())

	// Apply overlay style
	modal := overlayStyle.Render(content.String())

	// Center the modal with backdrop
	return m.renderWithBackdrop(modal)
}

// renderButtons renders the modal buttons.
func (m *Modal) renderButtons() string {
	buttonStyle := lipgloss.NewStyle().
		Padding(0, 2).
		MarginRight(1)

	focusedButtonStyle := buttonStyle.
		Foreground(lipgloss.Color("86")).
		Bold(true).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("86"))

	var buttons []string
	for i, label := range m.buttons {
		if i == m.focusIndex {
			buttons = append(buttons, focusedButtonStyle.Render(label))
		} else {
			buttons = append(buttons, buttonStyle.Render(label))
		}
	}

	return lipgloss.JoinHorizontal(lipgloss.Center, buttons...)
}

// renderWithBackdrop renders the modal with a semi-transparent backdrop.
func (m *Modal) renderWithBackdrop(modal string) string {
	// Get terminal dimensions (this is simplified, in real app you'd get actual size)
	width := 80
	height := 24

	// Overlay the modal on the backdrop
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, modal, lipgloss.WithWhitespaceBackground(lipgloss.Color("236")))
}

// handleButtonPress handles button selection and returns the appropriate result.
func (m *Modal) handleButtonPress(index int) ModalResult {
	switch m.modalType {
	case ModalTypeConfirm:
		return ModalResult{
			Confirmed: index == 0, // Yes is at index 0
			Canceled:  index == 1, // No is at index 1
		}
	case ModalTypeInput:
		if index == 0 { // OK
			return ModalResult{
				Input:     m.textInput.Value(),
				Confirmed: true,
			}
		}
		return ModalResult{Canceled: true}
	case ModalTypeInfo, ModalTypeError:
		return ModalResult{Confirmed: true}
	default:
		return ModalResult{Canceled: true}
	}
}

// Focus returns whether the modal should capture focus.
func (m *Modal) Focus() bool {
	return true
}

// SetSize updates the modal dimensions.
func (m *Modal) SetSize(width, height int) {
	m.width = min(width-4, 80)
	m.height = min(height-4, 20)
	if m.modalType == ModalTypeInput {
		m.textInput.Width = m.width - 4
	}
}
