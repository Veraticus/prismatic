package ui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModal_Creation(t *testing.T) {
	tests := []struct {
		name         string
		title        string
		message      string
		wantButtons  []string
		modalType    ModalType
		wantFocus    int
		hasTextInput bool
	}{
		{
			name:        "confirmation modal",
			modalType:   ModalTypeConfirm,
			title:       "Confirm Action",
			message:     "Are you sure?",
			wantButtons: []string{"Yes", "No"},
			wantFocus:   1, // Default to No
		},
		{
			name:         "input modal",
			modalType:    ModalTypeInput,
			title:        "Enter Name",
			message:      "Please enter your name:",
			wantButtons:  []string{"OK", "Cancel"},
			wantFocus:    0,
			hasTextInput: true,
		},
		{
			name:        "info modal",
			modalType:   ModalTypeInfo,
			title:       "Information",
			message:     "Operation completed successfully.",
			wantButtons: []string{"OK"},
			wantFocus:   0,
		},
		{
			name:        "error modal",
			modalType:   ModalTypeError,
			title:       "Error",
			message:     "An error occurred.",
			wantButtons: []string{"OK"},
			wantFocus:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modal := NewModal(tt.modalType, tt.title, tt.message)

			assert.Equal(t, tt.modalType, modal.modalType)
			assert.Equal(t, tt.title, modal.title)
			assert.Equal(t, tt.message, modal.message)
			assert.Equal(t, tt.wantButtons, modal.buttons)
			assert.Equal(t, tt.wantFocus, modal.focusIndex)

			if tt.hasTextInput {
				assert.NotNil(t, modal.textInput)
			}
		})
	}
}

func TestModal_Options(t *testing.T) {
	t.Run("with placeholder", func(t *testing.T) {
		modal := NewModal(ModalTypeInput, "Input", "Enter value:",
			WithPlaceholder("Type here..."))
		assert.Equal(t, "Type here...", modal.placeholder)
	})

	t.Run("with validation", func(t *testing.T) {
		validationCalled := false
		validation := func(_ string) error {
			validationCalled = true
			return nil
		}

		modal := NewModal(ModalTypeInput, "Input", "Enter value:",
			WithValidation(validation))
		require.NotNil(t, modal.validation)

		// Test validation is set
		err := modal.validation("test")
		assert.NoError(t, err)
		assert.True(t, validationCalled)
	})

	t.Run("with callback", func(t *testing.T) {
		callbackCalled := false
		callback := func(_ ModalResult) {
			callbackCalled = true
		}

		modal := NewModal(ModalTypeConfirm, "Confirm", "Are you sure?",
			WithCallback(callback))
		require.NotNil(t, modal.callback)

		// Test callback
		modal.callback(ModalResult{Confirmed: true})
		assert.True(t, callbackCalled)
	})
}

func TestModal_KeyboardNavigation(t *testing.T) {
	tests := []struct {
		name       string
		wantResult ModalResult
		keys       []string
		modalType  ModalType
		wantFocus  int
	}{
		{
			name:      "confirm modal - tab navigation",
			modalType: ModalTypeConfirm,
			keys:      []string{"tab"},
			wantFocus: 0, // From No (1) to Yes (0)
		},
		{
			name:      "confirm modal - shift+tab navigation",
			modalType: ModalTypeConfirm,
			keys:      []string{"shift+tab"},
			wantFocus: 0, // From No (1) to Yes (0)
		},
		{
			name:      "confirm modal - arrow navigation",
			modalType: ModalTypeConfirm,
			keys:      []string{"left"},
			wantFocus: 0, // From No (1) to Yes (0)
		},
		{
			name:      "confirm modal - vim navigation",
			modalType: ModalTypeConfirm,
			keys:      []string{"h"},
			wantFocus: 0, // From No (1) to Yes (0)
		},
		{
			name:       "confirm modal - escape cancels",
			modalType:  ModalTypeConfirm,
			keys:       []string{"esc"},
			wantResult: ModalResult{Canceled: true},
		},
		{
			name:       "confirm modal - enter on Yes",
			modalType:  ModalTypeConfirm,
			keys:       []string{"left", "enter"},
			wantResult: ModalResult{Confirmed: true},
		},
		{
			name:       "confirm modal - space on No",
			modalType:  ModalTypeConfirm,
			keys:       []string{" "},
			wantResult: ModalResult{Canceled: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modal := NewModal(tt.modalType, "Test", "Test message")
			var lastMsg tea.Msg

			for _, key := range tt.keys {
				_, cmd := modal.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key), Alt: false})
				if cmd != nil {
					lastMsg = cmd()
				}
			}

			// Check focus if no result expected
			if lastMsg == nil {
				assert.Equal(t, tt.wantFocus, modal.focusIndex)
			} else {
				// Check result
				closeMsg, ok := lastMsg.(ModalClosedMsg)
				require.True(t, ok)
				assert.Equal(t, tt.wantResult, closeMsg.Result)
			}
		})
	}
}

func TestModal_InputModal(t *testing.T) {
	t.Run("text input and submission", func(t *testing.T) {
		modal := NewModal(ModalTypeInput, "Input", "Enter name:")

		// Type some text
		modal.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'J'}})
		modal.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
		modal.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
		modal.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})

		// Submit with Enter
		_, cmd := modal.Update(tea.KeyMsg{Type: tea.KeyEnter})
		require.NotNil(t, cmd)

		msg := cmd()
		closeMsg, ok := msg.(ModalClosedMsg)
		require.True(t, ok)
		assert.Equal(t, "John", closeMsg.Result.Input)
		assert.True(t, closeMsg.Result.Confirmed)
	})

	t.Run("input with validation", func(t *testing.T) {
		validationErr := assert.AnError
		modal := NewModal(ModalTypeInput, "Input", "Enter name:",
			WithValidation(func(s string) error {
				if s == "" {
					return validationErr
				}
				return nil
			}))

		// Try to submit empty input
		_, cmd := modal.Update(tea.KeyMsg{Type: tea.KeyEnter})
		assert.Nil(t, cmd) // Should not close due to validation error

		// Type valid input
		modal.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'A'}})

		// Now submit should work
		_, cmd = modal.Update(tea.KeyMsg{Type: tea.KeyEnter})
		require.NotNil(t, cmd)

		msg := cmd()
		closeMsg, ok := msg.(ModalClosedMsg)
		require.True(t, ok)
		assert.Equal(t, "A", closeMsg.Result.Input)
		assert.True(t, closeMsg.Result.Confirmed)
	})

	t.Run("cancel input modal", func(t *testing.T) {
		modal := NewModal(ModalTypeInput, "Input", "Enter name:")

		// Type some text
		modal.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'T', 'e', 's', 't'}})

		// Cancel with ESC
		_, cmd := modal.Update(tea.KeyMsg{Type: tea.KeyEsc})
		require.NotNil(t, cmd)

		msg := cmd()
		closeMsg, ok := msg.(ModalClosedMsg)
		require.True(t, ok)
		assert.True(t, closeMsg.Result.Canceled)
		assert.Empty(t, closeMsg.Result.Input) // Input should not be returned on cancel
	})
}

func TestModal_ButtonHandling(t *testing.T) {
	tests := []struct {
		name        string
		wantResult  ModalResult
		modalType   ModalType
		buttonIndex int
	}{
		{
			name:        "confirm Yes",
			modalType:   ModalTypeConfirm,
			buttonIndex: 0,
			wantResult:  ModalResult{Confirmed: true},
		},
		{
			name:        "confirm No",
			modalType:   ModalTypeConfirm,
			buttonIndex: 1,
			wantResult:  ModalResult{Canceled: true},
		},
		{
			name:        "input OK",
			modalType:   ModalTypeInput,
			buttonIndex: 0,
			wantResult:  ModalResult{Confirmed: true, Input: ""},
		},
		{
			name:        "input Cancel",
			modalType:   ModalTypeInput,
			buttonIndex: 1,
			wantResult:  ModalResult{Canceled: true},
		},
		{
			name:        "info OK",
			modalType:   ModalTypeInfo,
			buttonIndex: 0,
			wantResult:  ModalResult{Confirmed: true},
		},
		{
			name:        "error OK",
			modalType:   ModalTypeError,
			buttonIndex: 0,
			wantResult:  ModalResult{Confirmed: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modal := NewModal(tt.modalType, "Test", "Test")
			result := modal.handleButtonPress(tt.buttonIndex)
			assert.Equal(t, tt.wantResult, result)
		})
	}
}

func TestModal_WindowResize(t *testing.T) {
	modal := NewModal(ModalTypeConfirm, "Test", "Test message")

	// Initial size
	assert.Equal(t, 60, modal.width)
	assert.Equal(t, 10, modal.height)

	// Update with window size
	modal.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	assert.Equal(t, 80, modal.width)  // Capped at 80
	assert.Equal(t, 20, modal.height) // Capped at 20

	// Update with smaller window
	modal.Update(tea.WindowSizeMsg{Width: 40, Height: 15})
	assert.Equal(t, 36, modal.width)  // 40 - 4
	assert.Equal(t, 11, modal.height) // 15 - 4
}

func TestModal_View(t *testing.T) {
	tests := []struct {
		name        string
		title       string
		message     string
		checkOutput []string
		modalType   ModalType
	}{
		{
			name:        "confirm modal render",
			modalType:   ModalTypeConfirm,
			title:       "Delete File",
			message:     "Are you sure you want to delete this file?",
			checkOutput: []string{"Delete File", "Are you sure", "Yes", "No"},
		},
		{
			name:        "info modal render",
			modalType:   ModalTypeInfo,
			title:       "Success",
			message:     "Operation completed",
			checkOutput: []string{"Success", "Operation completed", "OK"},
		},
		{
			name:        "error modal render",
			modalType:   ModalTypeError,
			title:       "Error",
			message:     "Failed to save",
			checkOutput: []string{"Error", "Failed to save", "OK"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modal := NewModal(tt.modalType, tt.title, tt.message)
			output := modal.View()

			// Check that expected strings are in the output
			for _, expected := range tt.checkOutput {
				assert.Contains(t, output, expected)
			}
		})
	}
}

func TestModal_Callback(t *testing.T) {
	t.Run("callback on confirmation", func(t *testing.T) {
		var capturedResult ModalResult
		callbackCalled := false

		modal := NewModal(ModalTypeConfirm, "Confirm", "Are you sure?",
			WithCallback(func(result ModalResult) {
				callbackCalled = true
				capturedResult = result
			}))

		// Select Yes and press Enter
		modal.focusIndex = 0
		_, cmd := modal.Update(tea.KeyMsg{Type: tea.KeyEnter})
		require.NotNil(t, cmd)
		cmd()

		assert.True(t, callbackCalled)
		assert.True(t, capturedResult.Confirmed)
		assert.False(t, capturedResult.Canceled)
	})

	t.Run("callback on cancellation", func(t *testing.T) {
		var capturedResult ModalResult
		callbackCalled := false

		modal := NewModal(ModalTypeInput, "Input", "Enter value:",
			WithCallback(func(result ModalResult) {
				callbackCalled = true
				capturedResult = result
			}))

		// Press ESC to cancel
		_, cmd := modal.Update(tea.KeyMsg{Type: tea.KeyEsc})
		require.NotNil(t, cmd)
		cmd()

		assert.True(t, callbackCalled)
		assert.False(t, capturedResult.Confirmed)
		assert.True(t, capturedResult.Canceled)
	})
}

func TestModal_Focus(t *testing.T) {
	modal := NewModal(ModalTypeConfirm, "Test", "Test")
	assert.True(t, modal.Focus())
}

func TestModal_SetSize(t *testing.T) {
	modal := NewModal(ModalTypeInput, "Test", "Test")

	// Set size
	modal.SetSize(100, 50)
	assert.Equal(t, 80, modal.width)           // Capped at 80
	assert.Equal(t, 20, modal.height)          // Capped at 20
	assert.Equal(t, 76, modal.textInput.Width) // width - 4

	// Set smaller size
	modal.SetSize(50, 15)
	assert.Equal(t, 46, modal.width)
	assert.Equal(t, 11, modal.height)
	assert.Equal(t, 42, modal.textInput.Width)
}
