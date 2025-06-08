// Package report provides functionality for generating HTML security reports from scan results.
// It includes support for applying manual modifications (suppressions, severity overrides, and
// comments) to findings, organizing findings by category and severity, and rendering
// professional HTML reports with a "prismatic" theme optimized for AI readability.
package report

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/internal/storage"
	"github.com/Veraticus/prismatic/pkg/logger"
	"github.com/Veraticus/prismatic/pkg/pathutil"
)

//go:embed templates/*
var templateFS embed.FS

// HTMLGenerator generates HTML reports from scan results.
type HTMLGenerator struct {
	logger           logger.Logger
	metadata         *models.ScanMetadata
	scanPath         string
	findings         []models.Finding
	enrichedFindings []models.EnrichedFinding
	useEnriched      bool
}

// NewHTMLGenerator creates a new HTML report generator.
func NewHTMLGenerator(scanPath string) (*HTMLGenerator, error) {
	return NewHTMLGeneratorWithLogger(scanPath, logger.GetGlobalLogger())
}

// NewHTMLGeneratorWithLogger creates a new HTML report generator with a custom logger.
func NewHTMLGeneratorWithLogger(scanPath string, log logger.Logger) (*HTMLGenerator, error) {
	// Load scan results
	store := storage.NewStorageWithLogger("data", log)

	// Resolve scan path
	if scanPath == "latest" {
		latest, err := store.FindLatestScan()
		if err != nil {
			return nil, fmt.Errorf("finding latest scan: %w", err)
		}
		scanPath = latest
	}

	// Load metadata
	metadata, err := store.LoadScanResults(scanPath)
	if err != nil {
		return nil, fmt.Errorf("loading scan results: %w", err)
	}

	// Load findings
	findingsPath := filepath.Join(scanPath, "findings.json")
	var findings []models.Finding
	if err := loadJSON(findingsPath, &findings); err != nil {
		return nil, fmt.Errorf("loading findings: %w", err)
	}

	// Check if enriched findings are available
	generator := &HTMLGenerator{
		scanPath: scanPath,
		metadata: metadata,
		findings: findings,
		logger:   log,
	}

	// Load enriched findings if available
	if len(metadata.EnrichedFindings) > 0 {
		generator.enrichedFindings = metadata.EnrichedFindings
		generator.useEnriched = true
		log.Info("Using enriched findings for report", "count", len(metadata.EnrichedFindings))
	}

	return generator, nil
}

// GetScanPath returns the scan path.
func (g *HTMLGenerator) GetScanPath() string {
	return g.scanPath
}

// GetMetadata returns the scan metadata.
func (g *HTMLGenerator) GetMetadata() *models.ScanMetadata {
	return g.metadata
}

// GetTotalFindings returns the total number of findings.
func (g *HTMLGenerator) GetTotalFindings() int {
	return len(g.findings)
}

// ApplyModifications applies manual modifications to the findings.
func (g *HTMLGenerator) ApplyModifications(modsPath string) error {
	mods, err := LoadModifications(modsPath)
	if err != nil {
		return fmt.Errorf("loading modifications: %w", err)
	}

	// Apply modifications
	g.findings = mods.ApplyModificationsWithLogger(g.findings, g.logger)

	g.logger.Info("Applied modifications",
		"file", modsPath,
		"suppressions", len(mods.Suppressions),
		"overrides", len(mods.Overrides))

	return nil
}

// Generate creates the HTML report.
func (g *HTMLGenerator) Generate(outputPath string) error {
	// Validate and clean the output path
	validOutputPath, err := pathutil.ValidateOutputPath(outputPath)
	if err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}

	// Parse templates
	tmpl, err := template.New("report").Funcs(g.templateFuncs()).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return fmt.Errorf("parsing templates: %w", err)
	}

	// Prepare template data
	data := g.prepareTemplateData()

	// Create output file
	if err = os.MkdirAll(filepath.Dir(validOutputPath), 0750); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	file, err := os.Create(validOutputPath)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing output file: %w", cerr)
		}
	}()

	// Execute template
	if err := tmpl.ExecuteTemplate(file, "report.html", data); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	g.logger.Info("Generated HTML report", "path", outputPath)
	return nil
}

// templateFuncs returns custom template functions.
func (g *HTMLGenerator) templateFuncs() template.FuncMap {
	return template.FuncMap{
		"severityClass": func(severity string) string {
			return fmt.Sprintf("severity-%s", severity)
		},
		"severityIcon": func(severity string) string {
			switch severity {
			case "critical":
				return "🔴"
			case "high":
				return "🟠"
			case "medium":
				return "🟡"
			case "low":
				return "🔵"
			default:
				return "⚪"
			}
		},
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"formatDuration": func(d time.Duration) string {
			return d.Round(time.Second).String()
		},
		"title": cases.Title(language.English).String,
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		"add": func(a, b int) int {
			return a + b
		},
	}
}

// TemplateData holds all data for the report template.
type TemplateData struct {
	GeneratedAt                time.Time
	Metadata                   *models.ScanMetadata
	AWSFindings                []models.Finding
	TopRisks                   []models.Finding
	IaCFindings                []models.Finding
	SecretsFindings            []models.Finding
	WebFindings                []models.Finding
	KubernetesFindings         []models.Finding
	ContainerFindings          []models.Finding
	AWSEnrichedFindings        []models.EnrichedFinding
	TopEnrichedRisks           []models.EnrichedFinding
	IaCEnrichedFindings        []models.EnrichedFinding
	SecretsEnrichedFindings    []models.EnrichedFinding
	WebEnrichedFindings        []models.EnrichedFinding
	KubernetesEnrichedFindings []models.EnrichedFinding
	ContainerEnrichedFindings  []models.EnrichedFinding
	TotalSuppressed            int
	InfoCount                  int
	LowCount                   int
	MediumCount                int
	HighCount                  int
	CriticalCount              int
	TotalActive                int
	ScanDuration               time.Duration
	UseEnriched                bool
}

// prepareTemplateData organizes data for the template.
func (g *HTMLGenerator) prepareTemplateData() *TemplateData {
	data := &TemplateData{
		Metadata:     g.metadata,
		GeneratedAt:  time.Now(),
		ScanDuration: g.metadata.EndTime.Sub(g.metadata.StartTime),
		UseEnriched:  g.useEnriched,
	}

	if g.useEnriched {
		// Process enriched findings
		g.prepareEnrichedData(data)
	} else {
		// Process regular findings
		g.prepareRegularData(data)
	}

	return data
}

// prepareRegularData processes regular findings for the template.
func (g *HTMLGenerator) prepareRegularData(data *TemplateData) {
	// Count findings by severity
	activeFindingsBySeverity := make(map[string][]models.Finding)

	for _, finding := range g.findings {
		if finding.Suppressed {
			data.TotalSuppressed++
			continue
		}

		data.TotalActive++
		activeFindingsBySeverity[finding.Severity] = append(activeFindingsBySeverity[finding.Severity], finding)

		// Categorize by scanner type
		switch finding.Scanner {
		case "prowler", "mock-prowler":
			data.AWSFindings = append(data.AWSFindings, finding)
		case "trivy", "mock-trivy":
			data.ContainerFindings = append(data.ContainerFindings, finding)
		case "kubescape", "mock-kubescape":
			data.KubernetesFindings = append(data.KubernetesFindings, finding)
		case "nuclei", "mock-nuclei":
			data.WebFindings = append(data.WebFindings, finding)
		case "gitleaks", "mock-gitleaks":
			data.SecretsFindings = append(data.SecretsFindings, finding)
		case "checkov", "mock-checkov":
			data.IaCFindings = append(data.IaCFindings, finding)
		}
	}

	// Set severity counts
	data.CriticalCount = len(activeFindingsBySeverity["critical"])
	data.HighCount = len(activeFindingsBySeverity["high"])
	data.MediumCount = len(activeFindingsBySeverity["medium"])
	data.LowCount = len(activeFindingsBySeverity["low"])
	data.InfoCount = len(activeFindingsBySeverity["info"])

	// Get top 10 risks (critical and high severity)
	var topRisks []models.Finding
	topRisks = append(topRisks, activeFindingsBySeverity["critical"]...)
	topRisks = append(topRisks, activeFindingsBySeverity["high"]...)

	// Sort by severity (critical first) and limit to 10
	sort.Slice(topRisks, func(i, j int) bool {
		if topRisks[i].Severity == topRisks[j].Severity {
			return topRisks[i].Title < topRisks[j].Title
		}
		return severityOrder(topRisks[i].Severity) < severityOrder(topRisks[j].Severity)
	})

	if len(topRisks) > 10 {
		topRisks = topRisks[:10]
	}
	data.TopRisks = topRisks

	// Sort findings within each category by severity
	sortFindings(data.AWSFindings)
	sortFindings(data.ContainerFindings)
	sortFindings(data.KubernetesFindings)
	sortFindings(data.WebFindings)
	sortFindings(data.SecretsFindings)
	sortFindings(data.IaCFindings)
}

// prepareEnrichedData processes enriched findings for the template.
func (g *HTMLGenerator) prepareEnrichedData(data *TemplateData) {
	// Count findings by severity
	activeFindingsBySeverity := make(map[string][]models.EnrichedFinding)

	for _, finding := range g.enrichedFindings {
		if finding.Suppressed {
			data.TotalSuppressed++
			continue
		}

		data.TotalActive++
		activeFindingsBySeverity[finding.Severity] = append(activeFindingsBySeverity[finding.Severity], finding)

		// Categorize by scanner type
		switch finding.Scanner {
		case "prowler", "mock-prowler":
			data.AWSEnrichedFindings = append(data.AWSEnrichedFindings, finding)
		case "trivy", "mock-trivy":
			data.ContainerEnrichedFindings = append(data.ContainerEnrichedFindings, finding)
		case "kubescape", "mock-kubescape":
			data.KubernetesEnrichedFindings = append(data.KubernetesEnrichedFindings, finding)
		case "nuclei", "mock-nuclei":
			data.WebEnrichedFindings = append(data.WebEnrichedFindings, finding)
		case "gitleaks", "mock-gitleaks":
			data.SecretsEnrichedFindings = append(data.SecretsEnrichedFindings, finding)
		case "checkov", "mock-checkov":
			data.IaCEnrichedFindings = append(data.IaCEnrichedFindings, finding)
		}
	}

	// Set severity counts
	data.CriticalCount = len(activeFindingsBySeverity["critical"])
	data.HighCount = len(activeFindingsBySeverity["high"])
	data.MediumCount = len(activeFindingsBySeverity["medium"])
	data.LowCount = len(activeFindingsBySeverity["low"])
	data.InfoCount = len(activeFindingsBySeverity["info"])

	// Get top 10 risks (critical and high severity)
	var topRisks []models.EnrichedFinding
	topRisks = append(topRisks, activeFindingsBySeverity["critical"]...)
	topRisks = append(topRisks, activeFindingsBySeverity["high"]...)

	// Sort by severity (critical first) and limit to 10
	sort.Slice(topRisks, func(i, j int) bool {
		if topRisks[i].Severity == topRisks[j].Severity {
			return topRisks[i].Title < topRisks[j].Title
		}
		return severityOrder(topRisks[i].Severity) < severityOrder(topRisks[j].Severity)
	})

	if len(topRisks) > 10 {
		topRisks = topRisks[:10]
	}
	data.TopEnrichedRisks = topRisks

	// Sort findings within each category by severity
	sortEnrichedFindings(data.AWSEnrichedFindings)
	sortEnrichedFindings(data.ContainerEnrichedFindings)
	sortEnrichedFindings(data.KubernetesEnrichedFindings)
	sortEnrichedFindings(data.WebEnrichedFindings)
	sortEnrichedFindings(data.SecretsEnrichedFindings)
	sortEnrichedFindings(data.IaCEnrichedFindings)
}

// severityOrder returns the sort order for severities.
func severityOrder(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	default:
		return 5
	}
}

// sortFindings sorts findings by severity and title.
func sortFindings(findings []models.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			return findings[i].Title < findings[j].Title
		}
		return severityOrder(findings[i].Severity) < severityOrder(findings[j].Severity)
	})
}

// sortEnrichedFindings sorts enriched findings by severity and title.
func sortEnrichedFindings(findings []models.EnrichedFinding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			return findings[i].Title < findings[j].Title
		}
		return severityOrder(findings[i].Severity) < severityOrder(findings[j].Severity)
	})
}

// loadJSON is a helper to load JSON files.
// The path should already be validated by the caller.
func loadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.Write(data)

	decoder := json.NewDecoder(&buf)
	return decoder.Decode(v)
}
