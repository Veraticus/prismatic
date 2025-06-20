// Package remediation provides types and functionality for generating remediation manifests and fix bundles.
package remediation

import (
	"fmt"
	"math"
	"time"

	"github.com/joshsymonds/prismatic/internal/models"
)

// Manifest represents a complete remediation manifest.
type Manifest struct {
	GeneratedAt     time.Time        `yaml:"generated_at"`
	ManifestVersion string           `yaml:"manifest_version"`
	ScanID          string           `yaml:"scan_id"`
	Remediations    []Remediation    `yaml:"remediations"`
	Metadata        ManifestMetadata `yaml:"metadata"`
}

// ManifestMetadata contains summary information about the manifest.
type ManifestMetadata struct {
	EstimatedTotalEffort   string  `yaml:"estimated_total_effort"`
	TotalFindings          int     `yaml:"total_findings"`
	ActionableRemediations int     `yaml:"actionable_remediations"`
	PriorityScore          float64 `yaml:"priority_score"`
}

// Remediation represents a single remediation action that may fix multiple findings.
type Remediation struct {
	Rollback       RollbackProcedure `yaml:"rollback"`
	Title          string            `yaml:"title"`
	Description    string            `yaml:"description"`
	Severity       string            `yaml:"severity"`
	ID             string            `yaml:"id"`
	Context        Context           `yaml:"context"`
	Target         Target            `yaml:"target"`
	Validation     []ValidationStep  `yaml:"validation"`
	FindingRefs    []string          `yaml:"finding_refs"`
	Dependencies   []string          `yaml:"dependencies"`
	Blocks         []string          `yaml:"blocks"`
	Implementation Implementation    `yaml:"implementation"`
	Priority       int               `yaml:"priority"`
}

// Target identifies where the fix should be applied.
type Target struct {
	RepositoryType  string           `yaml:"repository_type"`
	RepositoryHints []RepositoryHint `yaml:"repository_hints"`
	AffectedFiles   []FilePattern    `yaml:"affected_files"`
}

// RepositoryHint helps locate the repository or directory.
type RepositoryHint struct {
	Path string `yaml:"path"`
}

// FilePattern describes files to be modified.
type FilePattern struct {
	Pattern string `yaml:"pattern"`
}

// Context provides business and technical context.
type Context struct {
	BusinessImpact         string   `yaml:"business_impact"`
	DataAtRisk             string   `yaml:"data_at_risk"`
	ExploitationLikelihood string   `yaml:"exploitation_likelihood"`
	ComplianceViolations   []string `yaml:"compliance_violations"`
}

// Implementation describes how to implement the fix.
type Implementation struct {
	Approach         string       `yaml:"approach"`
	EstimatedEffort  string       `yaml:"estimated_effort"`
	LLMInstructions  string       `yaml:"llm_instructions"`
	CodeChanges      []CodeChange `yaml:"code_changes"`
	RequiresDowntime bool         `yaml:"requires_downtime"`
}

// CodeChange represents a specific code modification.
type CodeChange struct {
	FilePattern string `yaml:"file_pattern"`
	ChangeType  string `yaml:"change_type"`
	Description string `yaml:"description"`
	Template    string `yaml:"template"`
}

// ValidationStep describes how to verify the fix.
type ValidationStep struct {
	Step           string `yaml:"step"`
	Command        string `yaml:"command"`
	ExpectedOutput string `yaml:"expected_output"`
}

// RollbackProcedure describes how to undo the fix if needed.
type RollbackProcedure struct {
	Instructions string `yaml:"instructions"`
	Risk         string `yaml:"risk"`
}

// Group represents findings that can be fixed together.
type Group struct {
	Strategy        string
	RepositoryType  string
	Findings        []models.Finding
	Priority        int
	EstimatedEffort time.Duration
}

// RepositoryType constants.
const (
	RepoTypeTerraform      = "terraform"
	RepoTypeKubernetes     = "kubernetes"
	RepoTypeCloudFormation = "cloudformation"
	RepoTypeAnsible        = "ansible"
	RepoTypeDocker         = "docker"
	RepoTypeGeneric        = "generic"
)

// ChangeType constants.
const (
	ChangeTypeAddResource    = "add_resource"
	ChangeTypeModifyResource = "modify_resource"
	ChangeTypeDeleteResource = "delete_resource"
	ChangeTypeAddProperty    = "add_property"
	ChangeTypeModifyProperty = "modify_property"
	ChangeTypeReplaceValue   = "replace_value"
	ChangeTypeAddFile        = "add_file"
	ChangeTypePatch          = "patch"
)

// Priority levels for remediations.
const (
	PriorityUrgent   = 1
	PriorityHigh     = 2
	PriorityMedium   = 3
	PriorityLow      = 4
	PriorityDeferred = 5
)

// EstimateEffort converts a duration to a human-readable effort string.
func EstimateEffort(d time.Duration) string {
	switch {
	case d < 30*time.Minute:
		return "15-30 minutes"
	case d < time.Hour:
		return "30-60 minutes"
	case d < 2*time.Hour:
		return "1-2 hours"
	case d < 4*time.Hour:
		return "2-4 hours"
	case d < 8*time.Hour:
		return "4-8 hours"
	default:
		days := int(d.Hours() / 8)
		return fmt.Sprintf("%d+ days", days)
	}
}

// CalculatePriorityScore calculates a priority score based on severity and other factors.
func CalculatePriorityScore(remediations []Remediation) float64 {
	if len(remediations) == 0 {
		return 0.0
	}

	var totalScore float64
	for _, rem := range remediations {
		severityScore := getSeverityScore(rem.Severity)
		findingsCount := float64(len(rem.FindingRefs))

		// Weight by severity and number of findings addressed
		score := severityScore * (1 + findingsCount*0.1)
		totalScore += score
	}

	// Normalize to 0-10 scale
	avgScore := totalScore / float64(len(remediations))
	return math.Min(avgScore, 10.0)
}

func getSeverityScore(severity string) float64 {
	switch severity {
	case models.SeverityCritical:
		return 10.0
	case models.SeverityHigh:
		return 7.5
	case models.SeverityMedium:
		return 5.0
	case models.SeverityLow:
		return 2.5
	case models.SeverityInfo:
		return 1.0
	default:
		return 0.0
	}
}
