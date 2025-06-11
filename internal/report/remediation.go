// Package report provides functionality for generating security reports from scan results.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/joshsymonds/prismatic/internal/config"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/remediation"
	"github.com/joshsymonds/prismatic/pkg/logger"
	"github.com/joshsymonds/prismatic/pkg/pathutil"
)

// RemediationReporter generates YAML remediation manifests.
type RemediationReporter struct {
	config   *config.Config
	logger   logger.Logger
	grouper  *remediation.FindingGrouper
	metadata *models.ScanMetadata
}

// NewRemediationReporter creates a new remediation reporter.
func NewRemediationReporter(cfg *config.Config, log logger.Logger) *RemediationReporter {
	return &RemediationReporter{
		config:  cfg,
		logger:  log,
		grouper: remediation.NewFindingGrouper(cfg, log),
	}
}

// Generate creates a remediation manifest from findings.
func (r *RemediationReporter) Generate(findings []models.Finding, enrichments map[string]*enrichment.FindingEnrichment, metadata *models.ScanMetadata, outputPath string) error {
	r.metadata = metadata

	// Validate output path
	validPath, err := pathutil.ValidateOutputPath(outputPath)
	if err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}

	// Filter out suppressed findings
	var activeFindings []models.Finding
	for _, f := range findings {
		if !f.Suppressed {
			activeFindings = append(activeFindings, f)
		}
	}

	if len(activeFindings) == 0 {
		r.logger.Warn("No active findings to remediate")
		return r.writeEmptyManifest(validPath)
	}

	// Group findings by remediation strategy
	groups := r.grouper.GroupByRemediation(activeFindings, enrichments)

	// Create manifest
	manifest := r.createManifest(groups, enrichments)

	// Write YAML output
	return r.writeYAML(manifest, validPath)
}

// Name returns the format identifier.
func (r *RemediationReporter) Name() string {
	return "remediation"
}

// Description returns a human-readable description.
func (r *RemediationReporter) Description() string {
	return "YAML manifest with structured remediation instructions"
}

// createManifest builds the complete remediation manifest.
func (r *RemediationReporter) createManifest(groups []remediation.RemediationGroup, enrichments map[string]*enrichment.FindingEnrichment) *remediation.Manifest {
	manifest := &remediation.Manifest{
		ManifestVersion: "1.0",
		GeneratedAt:     time.Now(),
		ScanID:          r.metadata.ID,
		Remediations:    []remediation.Remediation{},
	}

	// Track total findings and effort
	totalFindings := 0
	totalEffort := time.Duration(0)

	// Create remediations from groups
	for i, group := range groups {
		rem := r.createRemediation(group, enrichments, i+1)
		manifest.Remediations = append(manifest.Remediations, rem)

		totalFindings += len(group.Findings)
		totalEffort += group.EstimatedEffort
	}

	// Sort by priority
	r.prioritizeRemediations(manifest.Remediations)

	// Set metadata
	manifest.Metadata = remediation.ManifestMetadata{
		TotalFindings:          totalFindings,
		ActionableRemediations: len(manifest.Remediations),
		EstimatedTotalEffort:   remediation.EstimateEffort(totalEffort),
		PriorityScore:          remediation.CalculatePriorityScore(manifest.Remediations),
	}

	return manifest
}

// createRemediation creates a single remediation from a group of findings.
func (r *RemediationReporter) createRemediation(group remediation.RemediationGroup, enrichments map[string]*enrichment.FindingEnrichment, id int) remediation.Remediation {
	// Get the highest severity from the group
	severity := r.getHighestSeverity(group.Findings)

	// Collect finding IDs
	var findingRefs []string
	for _, f := range group.Findings {
		findingRefs = append(findingRefs, f.ID)
	}

	// Generate title and description based on strategy
	title, description := r.generateTitleAndDescription(group)

	// Create context from enrichments
	context := r.createContext(group.Findings, enrichments)

	// Get implementation details from strategy
	implementation := r.getImplementation(group)

	// Generate validation steps
	validation := r.generateValidation(group)

	return remediation.Remediation{
		ID:             fmt.Sprintf("rem-%03d", id),
		Title:          title,
		Description:    description,
		Severity:       severity,
		Priority:       group.Priority,
		FindingRefs:    findingRefs,
		Target:         r.createTarget(group),
		Context:        context,
		Implementation: implementation,
		Validation:     validation,
		Rollback:       r.createRollback(group),
		Dependencies:   []string{},
		Blocks:         []string{},
	}
}

// getHighestSeverity returns the highest severity from a group of findings.
func (r *RemediationReporter) getHighestSeverity(findings []models.Finding) string {
	severityOrder := map[string]int{
		models.SeverityCritical: 0,
		models.SeverityHigh:     1,
		models.SeverityMedium:   2,
		models.SeverityLow:      3,
		models.SeverityInfo:     4,
	}

	highest := models.SeverityInfo
	highestOrder := severityOrder[highest]

	for _, f := range findings {
		if order, exists := severityOrder[f.Severity]; exists && order < highestOrder {
			highest = f.Severity
			highestOrder = order
		}
	}

	return highest
}

// generateTitleAndDescription creates human-readable title and description.
func (r *RemediationReporter) generateTitleAndDescription(group remediation.RemediationGroup) (string, string) {
	// This is a simplified version - in practice, you'd want more sophisticated logic
	switch group.Strategy {
	case "terraform-s3-public-access":
		return "Disable public access on S3 buckets",
			fmt.Sprintf("Multiple S3 buckets expose sensitive data publicly (%d findings)", len(group.Findings))
	case "kubernetes-security-context":
		return "Add security contexts to Kubernetes workloads",
			fmt.Sprintf("Multiple Kubernetes deployments lack proper security contexts (%d findings)", len(group.Findings))
	case "container-cve-updates":
		return "Update container images to patch CVEs",
			fmt.Sprintf("Multiple container images contain known vulnerabilities (%d findings)", len(group.Findings))
	default:
		return fmt.Sprintf("Fix %s issues", group.RepositoryType),
			fmt.Sprintf("Address %d security findings in %s resources", len(group.Findings), group.RepositoryType)
	}
}

// createContext generates context from enrichments.
func (r *RemediationReporter) createContext(findings []models.Finding, enrichments map[string]*enrichment.FindingEnrichment) remediation.RemediationContext {
	context := remediation.RemediationContext{
		ComplianceViolations: []string{},
	}

	// Aggregate context from all findings
	for _, f := range findings {
		if e, exists := enrichments[f.ID]; exists {
			// Add business impact
			if e.Analysis.BusinessImpact != "" && context.BusinessImpact == "" {
				context.BusinessImpact = e.Analysis.BusinessImpact
			}

			// Note: Compliance and exploitation likelihood aren't in the current enrichment model
			// These would need to be extracted from Analysis.TechnicalDetails or Context
		}
	}

	// Deduplicate compliance violations
	context.ComplianceViolations = deduplicateStrings(context.ComplianceViolations)

	return context
}

// createTarget generates the remediation target.
func (r *RemediationReporter) createTarget(group remediation.RemediationGroup) remediation.RemediationTarget {
	target := remediation.RemediationTarget{
		RepositoryType:  group.RepositoryType,
		RepositoryHints: []remediation.RepositoryHint{},
		AffectedFiles:   []remediation.FilePattern{},
	}

	// Add repository hints based on type
	switch group.RepositoryType {
	case remediation.RepoTypeTerraform:
		target.RepositoryHints = append(target.RepositoryHints,
			remediation.RepositoryHint{Path: "infrastructure/"},
			remediation.RepositoryHint{Path: "terraform/"})
		target.AffectedFiles = append(target.AffectedFiles,
			remediation.FilePattern{Pattern: "**/*.tf"},
			remediation.FilePattern{Pattern: "modules/**/*.tf"})
	case remediation.RepoTypeKubernetes:
		target.RepositoryHints = append(target.RepositoryHints,
			remediation.RepositoryHint{Path: "k8s/"},
			remediation.RepositoryHint{Path: "manifests/"})
		target.AffectedFiles = append(target.AffectedFiles,
			remediation.FilePattern{Pattern: "**/*.yaml"},
			remediation.FilePattern{Pattern: "**/*.yml"})
	case remediation.RepoTypeDocker:
		target.AffectedFiles = append(target.AffectedFiles,
			remediation.FilePattern{Pattern: "**/Dockerfile*"},
			remediation.FilePattern{Pattern: "**/.dockerignore"})
	}

	return target
}

// getImplementation returns implementation details for the remediation.
func (r *RemediationReporter) getImplementation(group remediation.RemediationGroup) remediation.Implementation {
	impl := remediation.Implementation{
		EstimatedEffort:  remediation.EstimateEffort(group.EstimatedEffort),
		RequiresDowntime: false,
		CodeChanges:      []remediation.CodeChange{},
	}

	// Generate strategy-specific implementation
	switch group.Strategy {
	case "terraform-s3-public-access":
		impl.Approach = "Add bucket ACLs and public access blocks"
		impl.LLMInstructions = `Locate all aws_s3_bucket resources and:
1. Set acl = "private" 
2. Add corresponding aws_s3_bucket_public_access_block resources
3. Ensure all four block settings are true`
		impl.CodeChanges = append(impl.CodeChanges, remediation.CodeChange{
			FilePattern: "**/*.tf",
			ChangeType:  remediation.ChangeTypeAddResource,
			Description: "Add public access block for each bucket",
			Template: `resource "aws_s3_bucket_public_access_block" "{{ bucket_name }}" {
  bucket = aws_s3_bucket.{{ bucket_name }}.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
		})
	case "kubernetes-security-context":
		impl.Approach = "Add security contexts to pod specifications"
		impl.LLMInstructions = `For each Deployment, StatefulSet, or DaemonSet:
1. Add securityContext to the pod spec
2. Set runAsNonRoot: true
3. Set readOnlyRootFilesystem: true where possible
4. Drop all capabilities and add only required ones`
		impl.CodeChanges = append(impl.CodeChanges, remediation.CodeChange{
			FilePattern: "**/*.yaml",
			ChangeType:  remediation.ChangeTypeAddProperty,
			Description: "Add security context to pod spec",
			Template: `securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 2000
  capabilities:
    drop:
    - ALL`,
		})
	}

	return impl
}

// generateValidation creates validation steps.
func (r *RemediationReporter) generateValidation(group remediation.RemediationGroup) []remediation.ValidationStep {
	var steps []remediation.ValidationStep

	switch group.Strategy {
	case "terraform-s3-public-access":
		steps = append(steps,
			remediation.ValidationStep{
				Step:           "Check bucket ACL",
				Command:        "aws s3api get-bucket-acl --bucket {{ bucket_name }}",
				ExpectedOutput: "No public-read grants",
			},
			remediation.ValidationStep{
				Step:           "Verify public access block",
				Command:        "aws s3api get-public-access-block --bucket {{ bucket_name }}",
				ExpectedOutput: "All settings true",
			})
	case "kubernetes-security-context":
		steps = append(steps,
			remediation.ValidationStep{
				Step:           "Check pod security context",
				Command:        "kubectl get pod {{ pod_name }} -o jsonpath='{.spec.securityContext}'",
				ExpectedOutput: "runAsNonRoot: true",
			})
	}

	return steps
}

// createRollback generates rollback instructions.
func (r *RemediationReporter) createRollback(group remediation.RemediationGroup) remediation.RollbackProcedure {
	switch group.Strategy {
	case "terraform-s3-public-access":
		return remediation.RollbackProcedure{
			Instructions: "Remove public access block resources and revert ACL changes",
			Risk:         "None - this change only restricts access",
		}
	case "kubernetes-security-context":
		return remediation.RollbackProcedure{
			Instructions: "Remove security context from pod specifications",
			Risk:         "Low - may restore previous functionality if apps require root",
		}
	default:
		return remediation.RollbackProcedure{
			Instructions: "Revert changes using version control",
			Risk:         "Varies based on specific changes",
		}
	}
}

// prioritizeRemediations sorts remediations by priority.
func (r *RemediationReporter) prioritizeRemediations(remediations []remediation.Remediation) {
	sort.Slice(remediations, func(i, j int) bool {
		// First by priority level
		if remediations[i].Priority != remediations[j].Priority {
			return remediations[i].Priority < remediations[j].Priority
		}
		// Then by severity
		return severityOrder(remediations[i].Severity) < severityOrder(remediations[j].Severity)
	})
}

// writeYAML writes the manifest to a YAML file.
func (r *RemediationReporter) writeYAML(manifest *remediation.Manifest, outputPath string) error {
	// Create output directory if needed
	if err := os.MkdirAll(filepath.Dir(outputPath), 0750); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	// Create output file
	file, err := os.Create(outputPath) // #nosec G304 - path is validated
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing output file: %w", cerr)
		}
	}()

	// Configure YAML encoder
	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)

	// Write manifest
	if err := encoder.Encode(manifest); err != nil {
		return fmt.Errorf("encoding manifest: %w", err)
	}

	r.logger.Info("Generated remediation manifest", "path", outputPath)
	return nil
}

// writeEmptyManifest writes a manifest with no remediations.
func (r *RemediationReporter) writeEmptyManifest(outputPath string) error {
	manifest := &remediation.Manifest{
		ManifestVersion: "1.0",
		GeneratedAt:     time.Now(),
		ScanID:          r.metadata.ID,
		Metadata: remediation.ManifestMetadata{
			TotalFindings:          0,
			ActionableRemediations: 0,
			EstimatedTotalEffort:   "0 hours",
			PriorityScore:          0.0,
		},
		Remediations: []remediation.Remediation{},
	}

	return r.writeYAML(manifest, outputPath)
}

// deduplicateStrings removes duplicate strings from a slice.
func deduplicateStrings(strings []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, s := range strings {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}
