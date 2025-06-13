package bubbletea

import (
	"fmt"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/joshsymonds/prismatic/internal/ui"
	"github.com/stretchr/testify/assert"
)

func TestModel_QuitKeys(t *testing.T) {
	model := Model{
		width:         80,
		height:        24,
		infoMaxHeight: 10,
		errors:        NewRingBuffer[ErrorEntry](5),
	}

	// Test 'q' key
	updatedModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	assert.True(t, updatedModel.(Model).stopped)
	assert.NotNil(t, cmd)
	// The command should be tea.Quit

	// Reset model
	model.stopped = false

	// Test 'Q' key
	updatedModel, cmd = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'Q'}})
	assert.True(t, updatedModel.(Model).stopped)
	assert.NotNil(t, cmd)

	// Reset model
	model.stopped = false

	// Test Ctrl+C
	updatedModel, cmd = model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	assert.True(t, updatedModel.(Model).stopped)
	assert.NotNil(t, cmd)
}

func TestModel_QuitHintInView(t *testing.T) {
	// Test without scrollable content
	model := Model{
		width:         80,
		height:        24,
		infoMaxHeight: 10,
		errors:        NewRingBuffer[ErrorEntry](5),
	}

	view := model.View()
	assert.Contains(t, view, "Press q or Ctrl+C to quit")

	// Test with scrollable content - need to use larger ring buffer
	model2 := Model{
		width:         80,
		height:        24,
		infoMaxHeight: 3, // Lower max height to trigger scrolling
		errors:        NewRingBuffer[ErrorEntry](10), // Larger buffer
	}
	
	// Add more errors than max height
	for i := 0; i < 5; i++ {
		model2.errors.Add(ErrorEntry{
			Scanner: "test",
			Message: fmt.Sprintf("Error message %d", i),
		})
	}

	view2 := model2.View()
	assert.Contains(t, view2, "q = quit")
}

func TestAdapter_Stop(t *testing.T) {
	// Test that Stop() properly closes resources and sends quit
	config := ui.Config{
		OutputDir:   "/tmp/test",
		ClientName:  "TestClient", 
		Environment: "test",
		StartTime:   time.Now(),
	}
	
	adapter := NewScannerUIAdapter(config)
	
	// Verify adapter is not stopped initially
	assert.False(t, adapter.IsStopped())
	
	// Stop the adapter
	adapter.Stop()
	
	// Verify it's marked as stopped
	assert.True(t, adapter.IsStopped())
	
	// Calling Stop() again should be safe
	adapter.Stop()
	assert.True(t, adapter.IsStopped())
}