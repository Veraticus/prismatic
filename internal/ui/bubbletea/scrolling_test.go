package bubbletea

import (
	"fmt"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
)

func TestModel_Scrolling(t *testing.T) {
	// Create model with errors that exceed the max height
	model := Model{
		errors:        NewRingBuffer[ErrorEntry](20),
		infoMaxHeight: 5, // Only show 5 lines at a time
		width:         80,
		height:        24,
	}

	// Add 10 errors to exceed the max height
	for i := 0; i < 10; i++ {
		model.errors.Add(ErrorEntry{
			Scanner:   "test-scanner",
			Message:   fmt.Sprintf("Error message %d", i+1),
			Timestamp: time.Now(),
		})
	}

	// Test initial state
	assert.Equal(t, 0, model.infoScrollOffset)

	// Test scrolling down
	updatedModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyDown})
	assert.Equal(t, 1, updatedModel.(Model).infoScrollOffset)

	// Test vim key 'j' for down
	updatedModel, _ = updatedModel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	assert.Equal(t, 2, updatedModel.(Model).infoScrollOffset)

	// Test scrolling up
	updatedModel, _ = updatedModel.Update(tea.KeyMsg{Type: tea.KeyUp})
	assert.Equal(t, 1, updatedModel.(Model).infoScrollOffset)

	// Test vim key 'k' for up
	updatedModel, _ = updatedModel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	assert.Equal(t, 0, updatedModel.(Model).infoScrollOffset)

	// Test that we can't scroll below 0
	updatedModel, _ = updatedModel.Update(tea.KeyMsg{Type: tea.KeyUp})
	assert.Equal(t, 0, updatedModel.(Model).infoScrollOffset)

	// Test Home key
	model.infoScrollOffset = 5
	updatedModel, _ = model.Update(tea.KeyMsg{Type: tea.KeyHome})
	assert.Equal(t, 0, updatedModel.(Model).infoScrollOffset)

	// Test PageDown
	updatedModel, _ = updatedModel.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	expectedOffset := model.infoMaxHeight / 2
	assert.Equal(t, expectedOffset, updatedModel.(Model).infoScrollOffset)

	// Test vim 'g' for go to top
	model.infoScrollOffset = 5
	updatedModel, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	assert.Equal(t, 0, updatedModel.(Model).infoScrollOffset)

	// Test vim 'G' for go to bottom (sets to very high number)
	updatedModel, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'G'}})
	assert.Equal(t, 999999, updatedModel.(Model).infoScrollOffset)
}

func TestModel_ScrollableBoxRendering(t *testing.T) {
	model := Model{
		width:            80,
		height:           24,
		infoMaxHeight:    3,
		infoScrollOffset: 0,
	}

	// Test with fewer lines than max height
	lines := []string{"Line 1", "Line 2"}
	box := model.renderScrollableBox("Test", lines)
	assert.Contains(t, box, "Line 1")
	assert.Contains(t, box, "Line 2")
	assert.NotContains(t, box, "More above")
	assert.NotContains(t, box, "More below")

	// Test with more lines than max height
	lines = []string{"Line 1", "Line 2", "Line 3", "Line 4", "Line 5"}
	box = model.renderScrollableBox("Test", lines)
	assert.Contains(t, box, "Test (1-3 of 5)")
	assert.Contains(t, box, "Line 1")
	assert.Contains(t, box, "Line 2")
	assert.Contains(t, box, "Line 3")
	assert.NotContains(t, box, "Line 4")
	assert.NotContains(t, box, "Line 5")
	assert.NotContains(t, box, "More above")
	assert.Contains(t, box, "More below")

	// Test scrolled position
	model.infoScrollOffset = 2
	box = model.renderScrollableBox("Test", lines)
	assert.Contains(t, box, "Test (3-5 of 5)")
	assert.NotContains(t, box, "Line 1")
	assert.NotContains(t, box, "Line 2")
	assert.Contains(t, box, "Line 3")
	assert.Contains(t, box, "Line 4")
	assert.Contains(t, box, "Line 5")
	assert.Contains(t, box, "More above")
	assert.NotContains(t, box, "More below")
}