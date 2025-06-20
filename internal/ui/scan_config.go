package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/joshsymonds/prismatic/internal/scanner"
)

// ScanConfig represents the scanner configuration page.
type ScanConfig struct {
	registry       *scanner.Registry
	scannerConfigs map[string]scanner.Config
	activeModal    *ScannerConfigModal
	fields         []ScanConfigField
	scanners       []ScannerOption
	cursor         int
	width          int
	height         int
	modalVisible   bool
}

// ScanConfigField represents a configuration field in the scan config page.
type ScanConfigField struct {
	Label    string
	Value    string
	Editable bool
	Focused  bool
}

// ScannerOption represents a scanner that can be enabled/disabled.
type ScannerOption struct {
	Factory     scanner.Factory
	Name        string
	Description string
	Enabled     bool
	Configured  bool
}

// NewScanConfig creates a new scanner configuration page.
func NewScanConfig() *ScanConfig {
	s := &ScanConfig{
		fields: []ScanConfigField{
			{Label: "Client Name", Value: "", Editable: true},
			{Label: "Environment", Value: "production", Editable: true},
			{Label: "Config File", Value: "", Editable: true},
			{Label: "Output Directory", Value: "./data/scans", Editable: true},
		},
		scannerConfigs: make(map[string]scanner.Config),
		cursor:         0,
	}

	// Use the global default registry
	s.registry = scanner.DefaultRegistry
	s.initializeScanners()

	return s
}

// initializeScanners loads available scanners from the registry.
func (s *ScanConfig) initializeScanners() {
	// Get all registered scanner names
	registeredNames := s.registry.List()

	// If we have registered scanners, use them
	if len(registeredNames) > 0 {
		s.scanners = make([]ScannerOption, 0, len(registeredNames))

		for _, name := range registeredNames {
			factory, err := s.registry.Get(name)
			if err != nil {
				continue // Skip if we can't get the factory
			}

			// Get description based on scanner capabilities
			description := getDefaultDescription(name, factory.Capabilities())

			s.scanners = append(s.scanners, ScannerOption{
				Factory:     factory,
				Name:        name,
				Description: description,
				Enabled:     true,
				Configured:  false,
			})
		}
	} else {
		// Fallback to mock scanners if no scanners are registered
		s.scanners = []ScannerOption{
			{
				Name:        "Prowler",
				Enabled:     true,
				Description: "AWS Security Best Practices",
				Configured:  false,
			},
			{
				Name:        "Trivy",
				Enabled:     true,
				Description: "Container & IaC Scanning",
				Configured:  false,
			},
			{
				Name:        "Kubescape",
				Enabled:     true,
				Description: "Kubernetes Security",
				Configured:  false,
			},
			{
				Name:        "Nuclei",
				Enabled:     true,
				Description: "Web Vulnerability Scanning",
				Configured:  false,
			},
			{
				Name:        "Gitleaks",
				Enabled:     true,
				Description: "Secret Detection",
				Configured:  false,
			},
			{
				Name:        "Checkov",
				Enabled:     true,
				Description: "Infrastructure as Code",
				Configured:  false,
			},
		}
	}
}

// getDefaultDescription returns a description based on scanner capabilities.
func getDefaultDescription(name string, caps scanner.Capabilities) string {
	// Try to return a meaningful description based on capabilities
	var features []string

	if caps.SupportsImages {
		features = append(features, "Container")
	}
	if caps.SupportsFilesystems {
		features = append(features, "Filesystem")
	}
	if caps.SupportsRepositories {
		features = append(features, "Repository")
	}
	if caps.SupportsCloud {
		features = append(features, "Cloud")
	}
	if caps.SupportsKubernetes {
		features = append(features, "Kubernetes")
	}
	if caps.SupportsWeb {
		features = append(features, "Web")
	}

	if len(features) > 0 {
		return strings.Join(features, " & ") + " Scanning"
	}

	// Fallback descriptions for known scanners
	switch name {
	case "trivy":
		return "Container & IaC Scanning"
	case "prowler":
		return "AWS Security Best Practices"
	case "kubescape":
		return "Kubernetes Security"
	case "nuclei":
		return "Web Vulnerability Scanning"
	case "gitleaks":
		return "Secret Detection"
	case "checkov":
		return "Infrastructure as Code"
	default:
		return "Security Scanner"
	}
}

// Init initializes the scan configuration.
func (s *ScanConfig) Init() tea.Cmd {
	return nil
}

// Update handles scan configuration updates.
func (s *ScanConfig) Update(msg tea.Msg) (*ScanConfig, tea.Cmd) {
	var cmds []tea.Cmd

	// Handle modal updates first if visible
	if s.modalVisible && s.activeModal != nil {
		var cmd tea.Cmd
		s.activeModal, cmd = s.activeModal.Update(msg)

		// Check if modal closed
		if !s.activeModal.IsVisible() {
			s.modalVisible = false
			// Get config if saved
			if config, saved := s.activeModal.GetConfig(); saved {
				scannerName := s.scanners[s.cursor-len(s.fields)].Name
				s.scannerConfigs[scannerName] = config
				s.scanners[s.cursor-len(s.fields)].Configured = true
			}
			s.activeModal = nil
		}

		return s, cmd
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.width = msg.Width
		s.height = msg.Height
		if s.activeModal != nil {
			s.activeModal.SetSize(msg.Width, msg.Height)
		}

	case tea.KeyMsg:
		switch msg.String() {
		// Navigation
		case "tab", "j", "down":
			s.moveCursor(1)
		case "shift+tab", "k", "up":
			s.moveCursor(-1)
		// Toggle scanner
		case " ", "enter":
			if s.cursor >= len(s.fields) && s.cursor < len(s.fields)+len(s.scanners) {
				idx := s.cursor - len(s.fields)
				s.scanners[idx].Enabled = !s.scanners[idx].Enabled
			} else if s.cursor == len(s.fields)+len(s.scanners) {
				// Start scan button
				cmd := s.startScan()
				return s, cmd
			}
		// Configure scanner
		case "c":
			// Only handle 'c' for scanner configuration if not in a text field
			if s.cursor >= len(s.fields) && s.cursor < len(s.fields)+len(s.scanners) {
				idx := s.cursor - len(s.fields)
				scannerOpt := s.scanners[idx]

				// Use the actual factory if available, otherwise create a mock
				var factory scanner.Factory
				if scannerOpt.Factory != nil {
					factory = scannerOpt.Factory
				} else {
					// Fallback to mock factory for unregistered scanners
					factory = &mockFactory{name: scannerOpt.Name}
				}

				s.activeModal = NewScannerConfigModal(scannerOpt.Name, factory)
				s.modalVisible = true
				cmd := s.activeModal.Init()
				return s, cmd
			} else if s.cursor < len(s.fields) && s.fields[s.cursor].Focused {
				// If in a text field, treat 'c' as text input
				s.fields[s.cursor].Value += "c"
			}
		// Start scan
		case "ctrl+s":
			cmd := s.startScan()
			return s, cmd
		// Handle backspace specially
		case "backspace":
			if s.cursor < len(s.fields) && s.fields[s.cursor].Focused && s.fields[s.cursor].Value != "" {
				s.fields[s.cursor].Value = s.fields[s.cursor].Value[:len(s.fields[s.cursor].Value)-1]
			}
		// Text input for fields
		default:
			if s.cursor < len(s.fields) && s.fields[s.cursor].Focused {
				// Simple text input (TODO: Use proper text input component)
				if len(msg.String()) == 1 {
					s.fields[s.cursor].Value += msg.String()
				}
			}
		}
	}
	return s, tea.Batch(cmds...)
}

// View renders the scan configuration page.
func (s *ScanConfig) View() string {
	// If modal is visible, render it over the main view
	if s.modalVisible && s.activeModal != nil {
		return s.activeModal.View()
	}

	var b strings.Builder

	// Title
	title := TitleStyle.Render("Configure New Scan")
	b.WriteString(lipgloss.PlaceHorizontal(s.width, lipgloss.Center, title))
	b.WriteString("\n\n")

	// Configuration fields
	fieldStyle := lipgloss.NewStyle().
		Padding(0, 2).
		Width(s.width - 4)

	for i, field := range s.fields {
		focused := s.cursor == i
		b.WriteString(s.renderField(field, focused))
		b.WriteString("\n")
	}

	b.WriteString("\n")

	// Scanner selection
	titleNoMargin := TitleStyle
	titleNoMargin.MarginBottom(0)
	b.WriteString(fieldStyle.Render(titleNoMargin.Render("Select Scanners:")))
	b.WriteString("\n")

	for i, scanner := range s.scanners {
		focused := s.cursor == len(s.fields)+i
		b.WriteString(s.renderScanner(scanner, focused))
		b.WriteString("\n")
	}

	b.WriteString("\n")

	// Start button
	startButton := "[Start Scan]"
	if s.cursor == len(s.fields)+len(s.scanners) {
		startButton = SelectedItemStyle.Render("▸ " + startButton)
	} else {
		startButton = NormalItemStyle.Render("  " + startButton)
	}
	b.WriteString(lipgloss.PlaceHorizontal(s.width, lipgloss.Center, startButton))

	// Help
	b.WriteString("\n\n")
	help := HelpStyle.Render("Navigate: Tab/↑↓ • Toggle: Space • Configure: C • Start: Ctrl+S • Back: Esc")
	b.WriteString(lipgloss.PlaceHorizontal(s.width, lipgloss.Center, help))

	return b.String()
}

// SetSize updates the page dimensions.
func (s *ScanConfig) SetSize(width, height int) {
	s.width = width
	s.height = height
	if s.activeModal != nil {
		s.activeModal.SetSize(width, height)
	}
}

// renderField renders a configuration field.
func (s *ScanConfig) renderField(field ScanConfigField, focused bool) string {
	labelStyle := lipgloss.NewStyle().
		Width(20).
		Foreground(lipgloss.Color("#808080"))

	valueStyle := lipgloss.NewStyle().
		Width(40).
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#333333")).
		Padding(0, 1)

	if focused {
		valueStyle = valueStyle.BorderForeground(lipgloss.Color("#00FFFF"))
		field.Value += "│" // Simple cursor
	}

	label := labelStyle.Render(field.Label + ":")
	value := valueStyle.Render(field.Value)

	return lipgloss.JoinHorizontal(lipgloss.Left, "  ", label, value)
}

// renderScanner renders a scanner option.
func (s *ScanConfig) renderScanner(scanner ScannerOption, focused bool) string {
	checkbox := "[ ]"
	if scanner.Enabled {
		checkbox = "[✓]"
	}

	style := NormalItemStyle
	cursor := "  "
	if focused {
		style = SelectedItemStyle
		cursor = "▸ "
	}

	nameStyle := lipgloss.NewStyle().Width(15)
	descStyle := lipgloss.NewStyle().
		Width(40).
		Foreground(lipgloss.Color("#808080"))

	// Add configuration indicator
	configIndicator := ""
	if scanner.Configured {
		configIndicator = " ⚙"
		configStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))
		configIndicator = configStyle.Render(configIndicator)
	}

	line := fmt.Sprintf("%s%s %s%s %s",
		cursor,
		checkbox,
		nameStyle.Render(scanner.Name),
		configIndicator,
		descStyle.Render(scanner.Description))

	return style.Render(line)
}

// moveCursor moves the cursor up or down.
func (s *ScanConfig) moveCursor(delta int) {
	// Total positions: fields + scanners + start button
	totalPositions := len(s.fields) + len(s.scanners) + 1
	s.cursor += delta

	// Wrap around
	if s.cursor < 0 {
		s.cursor = totalPositions - 1
	} else if s.cursor >= totalPositions {
		s.cursor = 0
	}

	// Update field focus
	for i := range s.fields {
		s.fields[i].Focused = (i == s.cursor)
	}
}

// startScan initiates the scan with current configuration.
func (s *ScanConfig) startScan() tea.Cmd {
	// TODO: Validate configuration
	// TODO: Pass configuration to scanner
	return func() tea.Msg {
		return StartScanMsg{
			ClientName:     s.fields[0].Value,
			Environment:    s.fields[1].Value,
			ConfigFile:     s.fields[2].Value,
			OutputDir:      s.fields[3].Value,
			Scanners:       s.getEnabledScanners(),
			ScannerConfigs: s.scannerConfigs,
		}
	}
}

// getEnabledScanners returns a list of enabled scanner names.
func (s *ScanConfig) getEnabledScanners() []string {
	var enabled []string
	for _, scanner := range s.scanners {
		if scanner.Enabled {
			enabled = append(enabled, scanner.Name)
		}
	}
	return enabled
}

// StartScanMsg is sent when starting a new scan.
type StartScanMsg struct {
	ScannerConfigs map[string]scanner.Config
	ClientName     string
	Environment    string
	ConfigFile     string
	OutputDir      string
	Scanners       []string
}

// mockFactory is a temporary factory implementation for testing.
// TODO: Replace with actual scanner factories.
type mockFactory struct {
	name string
}

func (f *mockFactory) Name() string {
	return f.name
}

func (f *mockFactory) Create(_ string, _ scanner.Config, _ scanner.Targets) (scanner.Scanner, error) {
	return nil, fmt.Errorf("mock factory: not implemented")
}

func (f *mockFactory) DefaultConfig() scanner.Config {
	// Return a mock config for now
	return &mockConfig{}
}

func (f *mockFactory) Capabilities() scanner.Capabilities {
	// Return capabilities based on scanner type
	switch f.name {
	case "Trivy":
		return scanner.Capabilities{
			SupportsImages:       true,
			SupportsFilesystems:  true,
			SupportsRepositories: true,
			SupportsKubernetes:   true,
			SupportsConcurrency:  true,
			RequiresNetwork:      true,
		}
	case "Nuclei":
		return scanner.Capabilities{
			SupportsWeb:         true,
			SupportsConcurrency: true,
			RequiresNetwork:     true,
		}
	case "Gitleaks":
		return scanner.Capabilities{
			SupportsRepositories: true,
			SupportsFilesystems:  true,
			SupportsConcurrency:  true,
		}
	case "Prowler":
		return scanner.Capabilities{
			SupportsCloud:       true,
			SupportsConcurrency: true,
			RequiresNetwork:     true,
		}
	case "Kubescape":
		return scanner.Capabilities{
			SupportsKubernetes:  true,
			SupportsConcurrency: true,
			RequiresNetwork:     true,
		}
	case "Checkov":
		return scanner.Capabilities{
			SupportsFilesystems:  true,
			SupportsRepositories: true,
			SupportsConcurrency:  true,
		}
	default:
		return scanner.Capabilities{}
	}
}

// mockConfig is a temporary config implementation.
type mockConfig struct{}

func (c *mockConfig) Validate() error {
	return nil
}
