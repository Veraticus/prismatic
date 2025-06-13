# Bubbletea Scanner UI

This is the reactive scanner UI implementation using Charm's bubbletea and lipgloss libraries.

## Architecture

The UI follows the Model-View-Update (MVU) pattern:

- **Model** (`model.go`): Contains all UI state
- **Messages** (`messages.go`): Defines messages for state updates
- **View** (`view.go`): Renders the UI using lipgloss
- **Adapter** (`adapter.go`): Bridges the old interface with the new implementation

## Key Features

1. **Automatic terminal width handling** - Lipgloss handles responsive layouts
2. **Clean separation of concerns** - Model/View/Update pattern
3. **Better testing** - Model updates can be tested without rendering
4. **Smooth updates** - No flicker, automatic diffing
5. **Beautiful styling** - Professional theming with box drawing characters

## Testing

The implementation includes comprehensive tests:

```bash
# Run all UI tests
GO_TEST=true go test -v ./internal/ui/bubbletea/...
```

The `GO_TEST=true` environment variable prevents the bubbletea program from trying to interact with the terminal during tests.

## Components

### RingBuffer
A generic circular buffer implementation used for error logging that prevents unbounded memory growth.

### Table
A reusable table component that handles column width calculations and text truncation automatically.

### ScannerUIAdapter
Implements the existing `ui.UI` interface, allowing seamless integration without modifying scanner code.

## Benefits

1. **No manual ANSI escape sequences** - Lipgloss handles all terminal control
2. **Fixes width calculation bugs** - Especially at 120 character terminal width
3. **Cleaner code structure** - Reactive pattern is easier to reason about
4. **Better performance** - Only re-renders what changed
5. **Future extensibility** - Easy to add interactivity, animations, etc.