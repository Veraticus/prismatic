// Package report provides functionality for generating HTML security reports from scan results.
// It includes support for organizing findings by category and severity, and rendering
// professional HTML reports with a "prismatic" theme optimized for AI readability.
package report

import (
	"embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/storage"
	"github.com/joshsymonds/prismatic/pkg/logger"
	"github.com/joshsymonds/prismatic/pkg/pathutil"
)

//go:embed templates/*
var templateFS embed.FS

// scannerCategories maps scanner names to their categories.
var scannerCategories = map[string]string{
	"prowler":        "aws",
	"mock-prowler":   "aws",
	"trivy":          "container",
	"mock-trivy":     "container",
	"kubescape":      "kubernetes",
	"mock-kubescape": "kubernetes",
	"nuclei":         "web",
	"mock-nuclei":    "web",
	"gitleaks":       "secrets",
	"mock-gitleaks":  "secrets",
	"checkov":        "iac",
	"mock-checkov":   "iac",
}

// HTMLGenerator generates HTML reports from scan results.
type HTMLGenerator struct {
	logger      logger.Logger
	metadata    *models.ScanMetadata
	enrichments map[string]*enrichment.FindingEnrichment
	enrichMeta  *enrichment.Metadata
	findings    []models.Finding
	scanID      int64
}

// NewHTMLGenerator creates a new HTML report generator.
func NewHTMLGenerator(scanPath string) (*HTMLGenerator, error) {
	return NewHTMLGeneratorWithLogger(scanPath, logger.GetGlobalLogger())
}

// NewHTMLGeneratorWithLogger creates a new HTML report generator with a custom logger.
func NewHTMLGeneratorWithLogger(scanPath string, log logger.Logger) (*HTMLGenerator, error) {
	// Create database connection
	db, err := database.New(":memory:")
	if err != nil {
		return nil, fmt.Errorf("creating database: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Warn("failed to close database", "error", err)
		}
	}()

	return NewHTMLGeneratorWithDatabase(scanPath, db, log)
}

// NewHTMLGeneratorWithDatabase creates a new HTML report generator with an existing database.
func NewHTMLGeneratorWithDatabase(scanPath string, db *database.DB, log logger.Logger) (*HTMLGenerator, error) {
	// Create storage instance
	store := storage.NewStorageWithLogger(db, log)

	// Resolve scan ID
	var scanID int64
	var err error
	if scanPath == "latest" {
		scanID, err = store.FindLatestScan()
		if err != nil {
			return nil, fmt.Errorf("finding latest scan: %w", err)
		}
	} else {
		// Parse scan ID from string
		scanID, err = strconv.ParseInt(scanPath, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid scan ID: %w", err)
		}
	}

	// Load metadata
	metadata, err := store.LoadScanResults(scanID)
	if err != nil {
		return nil, fmt.Errorf("loading scan results: %w", err)
	}

	// Collect all findings from metadata
	var findings []models.Finding
	for _, result := range metadata.Results {
		findings = append(findings, result.Findings...)
	}

	// Note: Business context enrichment removed as config is no longer passed

	// Load AI enrichments if available
	aiEnrichments, enrichMeta, err := store.LoadEnrichments(scanID)
	if err != nil {
		log.Warn("Failed to load AI enrichments", "error", err)
		// Continue without AI enrichments
	}

	// Create enrichment map for quick lookup
	enrichmentMap := make(map[string]*enrichment.FindingEnrichment)
	for i := range aiEnrichments {
		enrichmentMap[aiEnrichments[i].FindingID] = &aiEnrichments[i]
	}

	generator := &HTMLGenerator{
		scanID:      scanID,
		metadata:    metadata,
		findings:    findings,
		logger:      log,
		enrichments: enrichmentMap,
		enrichMeta:  enrichMeta,
	}

	return generator, nil
}

// GetScanPath returns the scan path.
func (g *HTMLGenerator) GetScanPath() string {
	return fmt.Sprintf("%d", g.scanID)
}

// GetMetadata returns the scan metadata.
func (g *HTMLGenerator) GetMetadata() *models.ScanMetadata {
	return g.metadata
}

// GetTotalFindings returns the total number of findings.
func (g *HTMLGenerator) GetTotalFindings() int {
	return len(g.findings)
}

// ApplyModifications has been removed - modifications functionality is no longer supported

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

	file, err := os.Create(validOutputPath) // #nosec G304 - path is validated
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
		"join":  strings.Join,
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		"add": func(a, b int) int {
			return a + b
		},
		"dict": func(values ...any) (map[string]any, error) {
			if len(values)%2 != 0 {
				return nil, fmt.Errorf("dict requires even number of arguments")
			}
			dict := make(map[string]any, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings")
				}
				dict[key] = values[i+1]
			}
			return dict, nil
		},
	}
}

// TemplateData holds all data for the report template.
type TemplateData struct {
	GeneratedAt        time.Time
	Metadata           *models.ScanMetadata
	FindingsByCategory map[string][]models.Finding
	SeverityCounts     map[string]int
	EnrichmentMeta     *enrichment.Metadata
	Enrichments        map[string]*enrichment.FindingEnrichment
	ContainerFindings  []models.Finding
	SecretsFindings    []models.Finding
	WebFindings        []models.Finding
	KubernetesFindings []models.Finding
	IaCFindings        []models.Finding
	AWSFindings        []models.Finding
	TopRisks           []models.Finding
	LowCount           int
	MediumCount        int
	HighCount          int
	CriticalCount      int
	TotalActive        int
	ScanDuration       time.Duration
	InfoCount          int
	TotalSuppressed    int
	HasEnrichments     bool
}

// prepareTemplateData organizes data for the template.
func (g *HTMLGenerator) prepareTemplateData() *TemplateData {
	data := &TemplateData{
		Metadata:       g.metadata,
		GeneratedAt:    time.Now(),
		ScanDuration:   g.metadata.EndTime.Sub(g.metadata.StartTime),
		Enrichments:    g.enrichments,
		EnrichmentMeta: g.enrichMeta,
		HasEnrichments: len(g.enrichments) > 0,
	}

	// Process findings - no need to differentiate between enriched and regular
	g.prepareData(data)

	return data
}

// prepareData processes findings for the template.
func (g *HTMLGenerator) prepareData(data *TemplateData) {
	// Initialize maps
	data.FindingsByCategory = make(map[string][]models.Finding)
	data.SeverityCounts = make(map[string]int)
	activeFindingsBySeverity := make(map[string][]models.Finding)

	for _, finding := range g.findings {
		if finding.Suppressed {
			data.TotalSuppressed++
			// Include suppressed findings in categories so they can be shown
			if category, exists := scannerCategories[finding.Scanner]; exists {
				data.FindingsByCategory[category] = append(data.FindingsByCategory[category], finding)
			}
			continue
		}

		data.TotalActive++

		// Automatic severity counting
		data.SeverityCounts[finding.Severity]++
		activeFindingsBySeverity[finding.Severity] = append(activeFindingsBySeverity[finding.Severity], finding)

		// Automatic categorization using map
		if category, exists := scannerCategories[finding.Scanner]; exists {
			data.FindingsByCategory[category] = append(data.FindingsByCategory[category], finding)
		}
	}

	// Set legacy severity counts for backward compatibility
	data.CriticalCount = data.SeverityCounts["critical"]
	data.HighCount = data.SeverityCounts["high"]
	data.MediumCount = data.SeverityCounts["medium"]
	data.LowCount = data.SeverityCounts["low"]
	data.InfoCount = data.SeverityCounts["info"]

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

	// Sort each category
	for category := range data.FindingsByCategory {
		sortFindings(data.FindingsByCategory[category])
	}

	// Set legacy fields for backward compatibility
	data.AWSFindings = data.FindingsByCategory["aws"]
	data.ContainerFindings = data.FindingsByCategory["container"]
	data.KubernetesFindings = data.FindingsByCategory["kubernetes"]
	data.WebFindings = data.FindingsByCategory["web"]
	data.SecretsFindings = data.FindingsByCategory["secrets"]
	data.IaCFindings = data.FindingsByCategory["iac"]
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
