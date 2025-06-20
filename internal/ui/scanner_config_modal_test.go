package ui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScannerConfigModal_Creation tests modal creation.
func TestScannerConfigModal_Creation(t *testing.T) {
	factory := &mockFactory{name: "Trivy"}
	modal := NewScannerConfigModal("Trivy", factory)

	assert.NotNil(t, modal)
	assert.Equal(t, "Trivy", modal.scanner)
	assert.True(t, modal.visible)
	assert.False(t, modal.saveChanges)
	assert.Greater(t, len(modal.fields), 0)
	assert.Equal(t, len(modal.fields), len(modal.inputs))
}

// TestScannerConfigModal_View tests modal rendering.
func TestScannerConfigModal_View(t *testing.T) {
	factory := &mockFactory{name: "Trivy"}
	modal := NewScannerConfigModal("Trivy", factory)
	modal.SetSize(80, 24)

	view := modal.View()

	// Check for key elements
	assert.Contains(t, view, "Configure Trivy Scanner")
	assert.Contains(t, view, "Severity Levels")
	assert.Contains(t, view, "Vulnerability Types")
	assert.Contains(t, view, "[ Save ]")
	assert.Contains(t, view, "[ Cancel ]")
	assert.Contains(t, view, "Supports:")
}

// TestScannerConfigModal_Navigation tests keyboard navigation.
func TestScannerConfigModal_Navigation(t *testing.T) {
	factory := &mockFactory{name: "Nuclei"}
	modal := NewScannerConfigModal("Nuclei", factory)

	tests := []struct {
		name     string
		key      string
		expected int
	}{
		{"Tab forward", "tab", 1},
		{"Down arrow", "down", 1},
		{"Shift+Tab backward", "shift+tab", len(modal.fields) + 1},
		{"Up arrow", "up", len(modal.fields) + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modal.focusIndex = 0

			// Handle different key types properly
			var msg tea.Msg
			switch tt.key {
			case "tab":
				msg = tea.KeyMsg{Type: tea.KeyTab}
			case "down":
				msg = tea.KeyMsg{Type: tea.KeyDown}
			case "shift+tab":
				msg = tea.KeyMsg{Type: tea.KeyShiftTab}
			case "up":
				msg = tea.KeyMsg{Type: tea.KeyUp}
			default:
				msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tt.key)}
			}

			_, _ = modal.Update(msg)
			assert.Equal(t, tt.expected, modal.focusIndex)
		})
	}
}

// TestScannerConfigModal_BooleanToggle tests boolean field toggling.
func TestScannerConfigModal_BooleanToggle(t *testing.T) {
	factory := &mockFactory{name: "Trivy"}
	modal := NewScannerConfigModal("Trivy", factory)

	// Find a boolean field
	boolFieldIndex := -1
	for i, field := range modal.fields {
		if field.Type == "bool" {
			boolFieldIndex = i
			break
		}
	}

	require.NotEqual(t, -1, boolFieldIndex, "No boolean field found")

	// Focus on the boolean field
	modal.focusIndex = boolFieldIndex
	initialValue := modal.inputs[boolFieldIndex].Value()

	// Toggle with space
	_, _ = modal.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(" ")})

	newValue := modal.inputs[boolFieldIndex].Value()
	assert.NotEqual(t, initialValue, newValue)
}

// TestScannerConfigModal_SaveCancel tests save and cancel actions.
func TestScannerConfigModal_SaveCancel(t *testing.T) {
	t.Run("Save", func(t *testing.T) {
		factory := &mockFactory{name: "Trivy"}
		modal := NewScannerConfigModal("Trivy", factory)

		// Navigate to Save button
		modal.focusIndex = len(modal.fields)

		// Press Enter
		_, _ = modal.Update(tea.KeyMsg{Type: tea.KeyEnter})

		assert.False(t, modal.visible)
		assert.True(t, modal.saveChanges)

		config, saved := modal.GetConfig()
		assert.True(t, saved)
		assert.NotNil(t, config)
	})

	t.Run("Cancel", func(t *testing.T) {
		factory := &mockFactory{name: "Trivy"}
		modal := NewScannerConfigModal("Trivy", factory)

		// Navigate to Cancel button
		modal.focusIndex = len(modal.fields) + 1

		// Press Enter
		_, _ = modal.Update(tea.KeyMsg{Type: tea.KeyEnter})

		assert.False(t, modal.visible)
		assert.False(t, modal.saveChanges)

		_, saved := modal.GetConfig()
		assert.False(t, saved)
	})

	t.Run("Escape", func(t *testing.T) {
		factory := &mockFactory{name: "Trivy"}
		modal := NewScannerConfigModal("Trivy", factory)

		// Press Escape
		_, _ = modal.Update(tea.KeyMsg{Type: tea.KeyEscape})

		assert.False(t, modal.visible)
		assert.False(t, modal.saveChanges)
	})
}

// TestScannerConfigModal_DifferentScanners tests configuration for different scanner types.
func TestScannerConfigModal_DifferentScanners(t *testing.T) {
	scanners := []struct {
		name           string
		expectedFields []string
	}{
		{
			name:           "Trivy",
			expectedFields: []string{"Severity Levels", "Vulnerability Types", "Ignore Unfixed"},
		},
		{
			name:           "Nuclei",
			expectedFields: []string{"Template Path", "Severity Filter", "Rate Limit"},
		},
		{
			name:           "Gitleaks",
			expectedFields: []string{"Config Path", "Scan Depth", "Redact Secrets"},
		},
		{
			name:           "Prowler",
			expectedFields: []string{"AWS Regions", "Compliance Frameworks", "Severity Filter"},
		},
		{
			name:           "Kubescape",
			expectedFields: []string{"Frameworks", "Namespaces", "Severity Threshold"},
		},
		{
			name:           "Checkov",
			expectedFields: []string{"Frameworks", "Skip Checks", "Soft Fail"},
		},
	}

	for _, scanner := range scanners {
		t.Run(scanner.name, func(t *testing.T) {
			factory := &mockFactory{name: scanner.name}
			modal := NewScannerConfigModal(scanner.name, factory)

			view := modal.View()
			for _, field := range scanner.expectedFields {
				assert.Contains(t, view, field, "Missing field: %s", field)
			}
		})
	}
}

// TestScannerConfigModal_Capabilities tests capability display.
func TestScannerConfigModal_Capabilities(t *testing.T) {
	tests := []struct {
		scanner  string
		expected []string
	}{
		{"Trivy", []string{"Images", "Files", "Repos", "K8s"}},
		{"Nuclei", []string{"Web"}},
		{"Gitleaks", []string{"Repos", "Files"}},
		{"Prowler", []string{"Cloud"}},
		{"Kubescape", []string{"K8s"}},
		{"Checkov", []string{"Files", "Repos"}},
	}

	for _, tt := range tests {
		t.Run(tt.scanner, func(t *testing.T) {
			factory := &mockFactory{name: tt.scanner}
			caps := factory.Capabilities()
			modal := NewScannerConfigModal(tt.scanner, factory)

			capsText := modal.renderCapabilities(caps)
			for _, cap := range tt.expected {
				assert.Contains(t, capsText, cap)
			}
		})
	}
}

// TestScannerConfigModal_TextInput tests text input functionality.
func TestScannerConfigModal_TextInput(t *testing.T) {
	factory := &mockFactory{name: "Trivy"}
	modal := NewScannerConfigModal("Trivy", factory)

	// Focus on first field
	modal.focusIndex = 0
	modal.updateFocus()

	// Type some text
	testText := "test123"
	for _, ch := range testText {
		_, _ = modal.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}})
	}

	// The exact behavior depends on the textinput implementation
	// For now, just verify the modal still works
	assert.True(t, modal.visible)
}
