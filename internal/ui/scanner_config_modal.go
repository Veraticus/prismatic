package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/joshsymonds/prismatic/internal/scanner"
)

// ScannerConfigModal represents a modal for configuring scanner-specific settings.
type ScannerConfigModal struct {
	scanner       string
	factory       scanner.Factory
	configBuilder *scannerConfigBuilder
	fields        []ConfigField
	inputs        []textinput.Model
	focusIndex    int
	width         int
	height        int
	visible       bool
	saveChanges   bool
}

// ConfigField represents a configuration field with metadata.
type ConfigField struct {
	Key         string
	Label       string
	Value       string
	Type        string
	Description string
	Options     []string
	Required    bool
}

// NewScannerConfigModal creates a new scanner configuration modal.
func NewScannerConfigModal(scannerName string, factory scanner.Factory) *ScannerConfigModal {
	m := &ScannerConfigModal{
		scanner:       scannerName,
		factory:       factory,
		visible:       true,
		configBuilder: newScannerConfigBuilder(scannerName, factory),
	}

	// Build fields based on scanner type
	m.fields = m.configBuilder.buildFields()

	// Create text inputs for each field
	m.inputs = make([]textinput.Model, len(m.fields))
	for i, field := range m.fields {
		ti := textinput.New()
		ti.SetValue(field.Value)
		ti.Placeholder = field.Label
		if i == 0 {
			ti.Focus()
		}
		m.inputs[i] = ti
	}

	return m
}

// Init initializes the modal.
func (m *ScannerConfigModal) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles modal updates.
func (m *ScannerConfigModal) Update(msg tea.Msg) (*ScannerConfigModal, tea.Cmd) {
	var cmds []tea.Cmd

	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.String() {
		case "esc":
			m.visible = false
			m.saveChanges = false
			return m, nil
		case "enter":
			if m.focusIndex == len(m.fields) {
				// Save button
				m.saveChanges = true
				m.visible = false
				return m, nil
			} else if m.focusIndex == len(m.fields)+1 {
				// Cancel button
				m.visible = false
				m.saveChanges = false
				return m, nil
			}
		case "tab", "down":
			m.focusIndex++
			if m.focusIndex > len(m.fields)+1 {
				m.focusIndex = 0
			}
			m.updateFocus()
		case "shift+tab", "up":
			m.focusIndex--
			if m.focusIndex < 0 {
				m.focusIndex = len(m.fields) + 1
			}
			m.updateFocus()
		case " ":
			// Toggle boolean fields
			if m.focusIndex < len(m.fields) && m.fields[m.focusIndex].Type == "bool" {
				currentVal := m.inputs[m.focusIndex].Value()
				newVal := "false"
				if currentVal == "false" {
					newVal = "true"
				}
				m.inputs[m.focusIndex].SetValue(newVal)
			}
		}
	}

	// Update text inputs
	for i := range m.inputs {
		if i == m.focusIndex && m.focusIndex < len(m.fields) {
			var cmd tea.Cmd
			m.inputs[i], cmd = m.inputs[i].Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
	}

	return m, tea.Batch(cmds...)
}

// View renders the modal.
func (m *ScannerConfigModal) View() string {
	if !m.visible {
		return ""
	}

	var b strings.Builder

	// Modal container
	modalStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00FFFF")).
		Padding(1, 2).
		Width(60).
		Background(lipgloss.Color("#1a1a1a"))

	// Title
	title := TitleStyle.Render(fmt.Sprintf("Configure %s Scanner", m.scanner))
	b.WriteString(title)
	b.WriteString("\n\n")

	// Scanner capabilities
	caps := m.factory.Capabilities()
	capsText := m.renderCapabilities(caps)
	b.WriteString(capsText)
	b.WriteString("\n\n")

	// Configuration fields
	for i, field := range m.fields {
		focused := i == m.focusIndex
		b.WriteString(m.renderField(field, m.inputs[i], focused))
		b.WriteString("\n")
	}

	b.WriteString("\n")

	// Buttons
	saveBtn := "[ Save ]"
	cancelBtn := "[ Cancel ]"

	if m.focusIndex == len(m.fields) {
		saveBtn = SelectedItemStyle.Render("▸ " + saveBtn)
	} else if m.focusIndex == len(m.fields)+1 {
		cancelBtn = SelectedItemStyle.Render("▸ " + cancelBtn)
	}

	buttons := lipgloss.JoinHorizontal(lipgloss.Left, saveBtn, "  ", cancelBtn)
	b.WriteString(lipgloss.PlaceHorizontal(56, lipgloss.Center, buttons))

	// Help
	b.WriteString("\n\n")
	help := HelpStyle.Render("Tab/↑↓: Navigate • Space: Toggle • Enter: Select • Esc: Cancel")
	b.WriteString(help)

	content := modalStyle.Render(b.String())

	// Center the modal
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
}

// SetSize updates the modal dimensions.
func (m *ScannerConfigModal) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// IsVisible returns whether the modal is visible.
func (m *ScannerConfigModal) IsVisible() bool {
	return m.visible
}

// GetConfig returns the configured scanner config if saved.
func (m *ScannerConfigModal) GetConfig() (scanner.Config, bool) {
	if !m.saveChanges {
		return nil, false
	}

	// Apply field values to config
	m.applyFieldsToConfig()

	return m.configBuilder.getConfig(), true
}

// renderCapabilities renders scanner capabilities.
func (m *ScannerConfigModal) renderCapabilities(caps scanner.Capabilities) string {
	capsStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#808080")).
		MarginBottom(1)

	var supported []string
	if caps.SupportsImages {
		supported = append(supported, "Images")
	}
	if caps.SupportsFilesystems {
		supported = append(supported, "Files")
	}
	if caps.SupportsRepositories {
		supported = append(supported, "Repos")
	}
	if caps.SupportsCloud {
		supported = append(supported, "Cloud")
	}
	if caps.SupportsKubernetes {
		supported = append(supported, "K8s")
	}
	if caps.SupportsWeb {
		supported = append(supported, "Web")
	}

	capsText := fmt.Sprintf("Supports: %s", strings.Join(supported, ", "))
	if caps.RequiresNetwork {
		capsText += " • Requires Network"
	}

	return capsStyle.Render(capsText)
}

// renderField renders a configuration field.
func (m *ScannerConfigModal) renderField(field ConfigField, input textinput.Model, focused bool) string {
	labelStyle := lipgloss.NewStyle().
		Width(24).
		Foreground(lipgloss.Color("#808080"))

	valueStyle := lipgloss.NewStyle().
		Width(35).
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#333333")).
		Padding(0, 1)

	if focused {
		valueStyle = valueStyle.BorderForeground(lipgloss.Color("#00FFFF"))
	}

	labelText := field.Label + ":"
	if field.Required {
		labelText += " *"
	}
	label := labelStyle.Render(labelText)

	var value string
	switch field.Type {
	case "bool":
		checkbox := "[ ]"
		if input.Value() == "true" {
			checkbox = "[✓]"
		}
		value = valueStyle.Render(checkbox + " " + field.Description)
	default:
		value = valueStyle.Render(input.View())
	}

	return lipgloss.JoinHorizontal(lipgloss.Left, label, value)
}

// updateFocus updates which input is focused.
func (m *ScannerConfigModal) updateFocus() {
	for i := range m.inputs {
		if i == m.focusIndex {
			m.inputs[i].Focus()
		} else {
			m.inputs[i].Blur()
		}
	}
}

// applyFieldsToConfig applies field values back to the scanner config.
func (m *ScannerConfigModal) applyFieldsToConfig() {
	// Collect input values
	values := make([]string, len(m.inputs))
	for i := range m.inputs {
		values[i] = m.inputs[i].Value()
	}

	// Apply to configuration
	if err := m.configBuilder.applyFields(m.fields, values); err != nil {
		// TODO: Handle validation errors in UI
		_ = err
	}
}

// Fields returns the configuration fields (for testing).
func (m *ScannerConfigModal) Fields() []ConfigField {
	return m.fields
}
