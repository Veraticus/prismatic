package ui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanConfig_Creation tests scan config page creation.
func TestScanConfig_Creation(t *testing.T) {
	config := NewScanConfig()

	assert.NotNil(t, config)
	assert.NotNil(t, config.registry)
	assert.Equal(t, 4, len(config.fields))
	// Should have at least one scanner (either registered or mock)
	assert.GreaterOrEqual(t, len(config.scanners), 1)
	assert.Equal(t, 0, config.cursor)
	assert.False(t, config.modalVisible)
}

// TestScanConfig_Navigation tests cursor navigation.
func TestScanConfig_Navigation(t *testing.T) {
	config := NewScanConfig()

	tests := []struct {
		name     string
		key      string
		expected int
	}{
		{"Tab forward", "tab", 1},
		{"Down arrow", "down", 1},
		{"Up arrow at top", "up", len(config.fields) + len(config.scanners)}, // Wraps to start button
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.cursor = 0

			// Handle different key types properly
			var msg tea.Msg
			switch tt.key {
			case "tab":
				msg = tea.KeyMsg{Type: tea.KeyTab}
			case "down":
				msg = tea.KeyMsg{Type: tea.KeyDown}
			case "up":
				msg = tea.KeyMsg{Type: tea.KeyUp}
			default:
				msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tt.key)}
			}

			_, _ = config.Update(msg)
			assert.Equal(t, tt.expected, config.cursor)
		})
	}
}

// TestScanConfig_ToggleScanner tests enabling/disabling scanners.
func TestScanConfig_ToggleScanner(t *testing.T) {
	config := NewScanConfig()

	// Move to first scanner
	config.cursor = len(config.fields)
	initialState := config.scanners[0].Enabled

	// Toggle with space
	_, _ = config.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(" ")})
	assert.NotEqual(t, initialState, config.scanners[0].Enabled)

	// Toggle again with enter
	_, _ = config.Update(tea.KeyMsg{Type: tea.KeyEnter})
	assert.Equal(t, initialState, config.scanners[0].Enabled)
}

// TestScanConfig_OpenModal tests opening scanner configuration modal.
func TestScanConfig_OpenModal(t *testing.T) {
	config := NewScanConfig()

	// Move to first scanner
	config.cursor = len(config.fields)

	// Press 'c' to configure
	_, cmd := config.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("c")})

	assert.True(t, config.modalVisible)
	assert.NotNil(t, config.activeModal)
	assert.NotNil(t, cmd)
}

// TestScanConfig_ModalInteraction tests modal save/cancel.
func TestScanConfig_ModalInteraction(t *testing.T) {
	config := NewScanConfig()
	config.SetSize(80, 24)

	// Open modal for first scanner
	config.cursor = len(config.fields)
	config.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("c")})

	require.True(t, config.modalVisible)
	require.NotNil(t, config.activeModal)

	// Save the modal
	config.activeModal.focusIndex = len(config.activeModal.fields) // Move to save button
	config.activeModal.saveChanges = true
	config.activeModal.visible = false

	// Update to process modal close
	_, _ = config.Update(tea.Msg(nil))

	assert.False(t, config.modalVisible)
	assert.True(t, config.scanners[0].Configured)
	assert.Contains(t, config.scannerConfigs, config.scanners[0].Name)
}

// TestScanConfig_StartScan tests start scan message generation.
func TestScanConfig_StartScan(t *testing.T) {
	config := NewScanConfig()

	// Set some values
	config.fields[0].Value = "test-client"
	config.fields[1].Value = "staging"
	config.fields[2].Value = "/path/to/config.yaml"
	config.fields[3].Value = "./output"

	// Enable only some scanners (disable others since all are enabled by default)
	// First, disable all scanners
	for i := range config.scanners {
		config.scanners[i].Enabled = false
	}

	// Then enable just the first two (or all if less than 2)
	numToEnable := 2
	if len(config.scanners) < numToEnable {
		numToEnable = len(config.scanners)
	}
	for i := 0; i < numToEnable; i++ {
		config.scanners[i].Enabled = true
	}

	// Move to start button
	config.cursor = len(config.fields) + len(config.scanners)

	// Press enter
	_, cmd := config.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.NotNil(t, cmd)

	// Execute command to get message
	msg := cmd()
	startMsg, ok := msg.(StartScanMsg)
	require.True(t, ok)

	assert.Equal(t, "test-client", startMsg.ClientName)
	assert.Equal(t, "staging", startMsg.Environment)
	assert.Equal(t, "/path/to/config.yaml", startMsg.ConfigFile)
	assert.Equal(t, "./output", startMsg.OutputDir)

	// Should have the number of scanners we enabled
	expectedCount := 2
	if len(config.scanners) < expectedCount {
		expectedCount = len(config.scanners)
	}
	assert.Equal(t, expectedCount, len(startMsg.Scanners))

	// The enabled scanners should be in the message
	for i := 0; i < expectedCount; i++ {
		assert.Contains(t, startMsg.Scanners, config.scanners[i].Name)
	}
	assert.NotNil(t, startMsg.ScannerConfigs)
}

// TestScanConfig_View tests rendering.
func TestScanConfig_View(t *testing.T) {
	config := NewScanConfig()
	config.SetSize(80, 24)

	view := config.View()

	// Check for key elements
	assert.Contains(t, view, "Configure New Scan")
	assert.Contains(t, view, "Client Name")
	assert.Contains(t, view, "Environment")
	assert.Contains(t, view, "Select Scanners")
	// Check that at least one scanner is shown
	if len(config.scanners) > 0 {
		assert.Contains(t, view, config.scanners[0].Name)
	}
	assert.Contains(t, view, "[Start Scan]")
	assert.Contains(t, view, "Configure: C")
}

// TestScanConfig_ConfiguredIndicator tests the configured indicator display.
func TestScanConfig_ConfiguredIndicator(t *testing.T) {
	config := NewScanConfig()
	config.SetSize(80, 24)

	// Only test if we have scanners
	if len(config.scanners) > 0 {
		// Mark first scanner as configured
		config.scanners[0].Configured = true

		view := config.View()

		// The configured scanner should show the gear indicator
		assert.Contains(t, view, "⚙")
	}
}

// TestScanConfig_TextInput tests basic text input in fields.
func TestScanConfig_TextInput(t *testing.T) {
	config := NewScanConfig()

	// Focus on first field
	config.cursor = 0
	config.fields[0].Focused = true

	// Type some characters
	testText := "myclient"
	for _, ch := range testText {
		_, _ = config.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}})
	}

	assert.Equal(t, testText, config.fields[0].Value)

	// Test backspace
	_, _ = config.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	assert.Equal(t, "myclien", config.fields[0].Value)
}

// TestScanConfig_GetEnabledScanners tests getting list of enabled scanners.
func TestScanConfig_GetEnabledScanners(t *testing.T) {
	config := NewScanConfig()

	// Skip test if we don't have any scanners
	if len(config.scanners) == 0 {
		t.Skip("No scanners to test")
	}

	// Disable all scanners first
	for i := range config.scanners {
		config.scanners[i].Enabled = false
	}

	// Enable specific scanners based on what's available
	enabledCount := 0
	enabledNames := []string{}

	// Enable every other scanner (up to 3)
	for i := 0; i < len(config.scanners) && enabledCount < 3; i += 2 {
		config.scanners[i].Enabled = true
		enabledNames = append(enabledNames, config.scanners[i].Name)
		enabledCount++
	}

	enabled := config.getEnabledScanners()

	assert.Equal(t, enabledCount, len(enabled))

	// Check that all enabled scanners are in the result
	for _, name := range enabledNames {
		assert.Contains(t, enabled, name)
	}

	// Check that disabled scanners are not in the result
	for i := 1; i < len(config.scanners); i += 2 {
		if !config.scanners[i].Enabled {
			assert.NotContains(t, enabled, config.scanners[i].Name)
		}
	}
}
