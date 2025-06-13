# Scanner UI Refactor Design Document

## Overview

This document outlines the refactor of Prismatic's scanner UI from an imperative stdout-based implementation to a reactive Charm bubbletea/lipgloss architecture.

## Current Architecture Analysis

### Problems with Current Implementation
- Manual ANSI escape sequence management
- Complex width calculations with edge cases
- Scattered state across multiple fields
- Direct stdout writes make testing difficult
- Concurrent updates require mutex locking
- No clean separation between data and presentation

### What Works Well
- Clean visual design with bordered boxes
- Real-time updates from concurrent scanners
- Final state persistence (screen doesn't clear)
- Responsive to terminal width changes

## New Architecture

### Core Components

```go
// Model represents the entire UI state
type Model struct {
    // Dimensions
    width       int
    height      int
    
    // Core state
    startTime   time.Time
    outputDir   string
    client      string
    environment string
    
    // Repository tracking
    repos       []RepoState
    repoIndex   map[string]int  // name -> index for O(1) updates
    
    // Scanner tracking  
    scanners    []ScannerState
    scannerIndex map[string]int  // name -> index
    
    // Error log (ring buffer)
    errors      *RingBuffer[ErrorEntry]
    
    // Display state
    showFinalSummary bool
    finalMessage     []string
    
    // Channels for external updates
    updates     chan Msg
}

type RepoState struct {
    Name      string
    Status    RepoStatus  // enum: pending|cloning|ready|failed
    Error     string
    UpdatedAt time.Time
}

type ScannerState struct {
    Name          string
    Status        ScannerStatus  // enum: pending|starting|running|success|failed
    StartTime     time.Time
    Duration      time.Duration
    Progress      Progress
    Findings      FindingSummary
    Message       string
    UpdatedAt     time.Time
}
```

### Message Types

```go
// Messages from scanner goroutines to UI
type Msg interface{}

// Repository messages
type RepoStatusMsg struct {
    Name      string
    Status    RepoStatus
    LocalPath string
    Error     error
}

// Scanner messages  
type ScannerStatusMsg struct {
    Scanner  string
    Status   *models.ScannerStatus
}

type ScannerErrorMsg struct {
    Scanner string
    Error   string
}

// Lifecycle messages
type FinalSummaryMsg struct {
    Lines []string
}

// Internal messages
type WindowSizeMsg struct {
    Width  int
    Height int
}

type TickMsg time.Time
```

### Update Function

```go
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg := msg.(type) {
    
    case RepoStatusMsg:
        m.updateRepo(msg)
        return m, nil
        
    case ScannerStatusMsg:
        m.updateScanner(msg)
        return m, nil
        
    case ScannerErrorMsg:
        m.addError(msg.Scanner, msg.Error)
        return m, nil
        
    case FinalSummaryMsg:
        m.showFinalSummary = true
        m.finalMessage = msg.Lines
        // Return tea.Quit but view will render one final time
        return m, tea.Quit
        
    case tea.WindowSizeMsg:
        m.width = msg.Width
        m.height = msg.Height
        return m, nil
        
    case tea.KeyMsg:
        // Allow Ctrl+C to quit
        if msg.Type == tea.KeyCtrlC {
            return m, tea.Quit
        }
        
    case TickMsg:
        // Update durations for running scanners
        m.updateElapsedTimes()
        return m, tickCmd()
    }
    
    return m, nil
}
```

### View Function with Lipgloss Styling

```go
func (m Model) View() string {
    if m.width == 0 {
        return "Initializing..."
    }
    
    sections := []string{
        m.renderHeader(),
        m.renderRepositories(), 
        m.renderScanners(),
        m.renderSummary(),
    }
    
    // Only show errors if present
    if m.errors.Len() > 0 {
        sections = append(sections, m.renderErrors())
    }
    
    // Show final summary if scan complete
    if m.showFinalSummary {
        sections = append(sections, m.renderFinalSummary())
    }
    
    return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

// Style definitions using lipgloss
var (
    // Base styles
    boxStyle = lipgloss.NewStyle().
        Border(lipgloss.RoundedBorder()).
        BorderForeground(lipgloss.Color("86"))  // Cyan
        
    titleStyle = lipgloss.NewStyle().
        Bold(true).
        Foreground(lipgloss.Color("86"))
        
    // Severity colors  
    criticalStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))  // Red
    highStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))  // Orange  
    mediumStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("226"))  // Yellow
    lowStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))   // Green
    
    // Status styles
    successIcon = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("✓")
    failIcon    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("✗")
    runningIcon = lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Render("⟳")
)
```

### Scanner Table Implementation

```go
func (m Model) renderScanners() string {
    if len(m.scanners) == 0 {
        return ""
    }
    
    // Create table with lipgloss
    headers := []string{"Scanner", "Status", "Time", "Progress"}
    rows := [][]string{}
    
    for _, scanner := range m.scanners {
        rows = append(rows, []string{
            scanner.Name,
            m.formatStatus(scanner.Status),
            m.formatDuration(scanner.Duration),
            m.formatProgress(scanner),
        })
    }
    
    table := Table{
        Headers: headers,
        Rows:    rows,
        Width:   m.width,
        Style:   boxStyle,
    }
    
    return table.Render()
}

// Custom table component using lipgloss
type Table struct {
    Headers []string
    Rows    [][]string
    Width   int
    Style   lipgloss.Style
}

func (t Table) Render() string {
    // Calculate column widths
    widths := t.calculateColumnWidths()
    
    // Render headers
    headerRow := t.renderRow(t.Headers, widths, titleStyle)
    
    // Render separator
    separator := t.renderSeparator(widths)
    
    // Render data rows
    dataRows := []string{}
    for _, row := range t.Rows {
        dataRows = append(dataRows, t.renderRow(row, widths, lipgloss.NewStyle()))
    }
    
    // Combine everything
    content := lipgloss.JoinVertical(
        lipgloss.Left,
        headerRow,
        separator,
        strings.Join(dataRows, "\n"),
    )
    
    return t.Style.Width(t.Width).Render(content)
}
```

### Integration Layer

```go
// ScannerUIAdapter bridges the old scanner interface with bubbletea
type ScannerUIAdapter struct {
    program *tea.Program
    model   *Model
}

func NewScannerUIAdapter(config Config) *ScannerUIAdapter {
    model := &Model{
        startTime:    config.StartTime,
        outputDir:    config.OutputDir,
        client:       config.ClientName,
        environment:  config.Environment,
        repos:        []RepoState{},
        repoIndex:    make(map[string]int),
        scanners:     []ScannerState{},
        scannerIndex: make(map[string]int),
        errors:       NewRingBuffer[ErrorEntry](5),  // Keep last 5 errors
        updates:      make(chan Msg, 100),
    }
    
    // Create program but don't start it yet
    program := tea.NewProgram(model, 
        tea.WithAltScreen(),       // Use alternate screen buffer
        tea.WithMouseCellMotion(), // Enable mouse support
    )
    
    return &ScannerUIAdapter{
        program: program,
        model:   model,
    }
}

// Implement existing ScannerUI interface methods
func (a *ScannerUIAdapter) Start() {
    go a.program.Run()
    
    // Start ticker for duration updates
    go func() {
        ticker := time.NewTicker(100 * time.Millisecond)
        defer ticker.Stop()
        
        for range ticker.C {
            a.program.Send(TickMsg(time.Now()))
        }
    }()
}

func (a *ScannerUIAdapter) UpdateRepository(name, status, localPath string, err error) {
    a.program.Send(RepoStatusMsg{
        Name:      name,
        Status:    ParseRepoStatus(status),
        LocalPath: localPath,
        Error:     err,
    })
}

func (a *ScannerUIAdapter) UpdateScanner(status *models.ScannerStatus) {
    a.program.Send(ScannerStatusMsg{
        Scanner: status.Scanner,
        Status:  status,
    })
}

func (a *ScannerUIAdapter) RenderFinalState(summaryLines []string) {
    a.program.Send(FinalSummaryMsg{Lines: summaryLines})
    
    // Wait for program to finish
    time.Sleep(100 * time.Millisecond)
}
```

### Terminal Width Handling

```go
func (m *Model) updateBoxWidth() int {
    // Lipgloss handles this automatically with responsive styles
    maxWidth := 120
    if m.width < maxWidth {
        return m.width
    }
    return maxWidth
}

// Responsive table column widths
func (t Table) calculateColumnWidths() []int {
    availableWidth := t.Width - 4  // Account for borders
    
    // Fixed widths for first 3 columns
    scannerWidth := 11
    statusWidth := 10  
    timeWidth := 8
    
    // Progress column gets remaining space
    progressWidth := availableWidth - scannerWidth - statusWidth - timeWidth - 9  // separators
    
    return []int{scannerWidth, statusWidth, timeWidth, progressWidth}
}
```

### Error Handling

```go
// Ring buffer for errors to avoid unbounded growth
type RingBuffer[T any] struct {
    items    []T
    head     int
    size     int
    capacity int
}

func (r *RingBuffer[T]) Add(item T) {
    if r.size < r.capacity {
        r.items = append(r.items, item)
        r.size++
    } else {
        r.items[r.head] = item
        r.head = (r.head + 1) % r.capacity
    }
}

func (r *RingBuffer[T]) Items() []T {
    if r.size < r.capacity {
        return r.items
    }
    // Return items in order
    result := make([]T, r.capacity)
    for i := 0; i < r.capacity; i++ {
        result[i] = r.items[(r.head+i)%r.capacity]
    }
    return result
}
```

## Migration Strategy

1. **Keep existing `ScannerUI` interface** - This allows the scanner code to remain unchanged
2. **Create `ScannerUIAdapter`** that implements the interface but uses bubbletea internally
3. **Add a feature flag** to switch between implementations during testing
4. **No changes needed to scanner code** - They continue calling `UpdateRepository`, `UpdateScanner`, etc.

## Benefits

1. **Automatic width handling** - Lipgloss handles responsive layouts
2. **Clean separation** - Model/View/Update pattern
3. **Better testing** - Can test model updates without rendering
4. **Smooth updates** - No flicker, automatic diffing
5. **Mouse support** - Could add interactivity later
6. **Beautiful styling** - Gradient borders, smooth animations

## Testing Strategy

```go
func TestScannerUpdates(t *testing.T) {
    model := Model{
        scanners: []ScannerState{},
        scannerIndex: make(map[string]int),
    }
    
    // Test scanner update
    msg := ScannerStatusMsg{
        Scanner: "nuclei",
        Status: &models.ScannerStatus{
            Status: models.StatusRunning,
            TotalFindings: 10,
        },
    }
    
    newModel, _ := model.Update(msg)
    m := newModel.(Model)
    
    assert.Equal(t, 1, len(m.scanners))
    assert.Equal(t, "nuclei", m.scanners[0].Name)
}
```

## Summary

This refactor will:
- Eliminate all manual width calculation bugs
- Provide a more maintainable architecture
- Enable future enhancements (interactivity, animations)
- Create a more professional, polished UI
- Maintain full compatibility with existing scanner code