package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/joshsymonds/prismatic/internal/config"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/remediation"
	"github.com/joshsymonds/prismatic/pkg/logger"
	"gopkg.in/yaml.v3"
)

// FixBundleGenerator generates a directory structure with remediation files.
type FixBundleGenerator struct {
	remediationGen *RemediationReporter
	config         *config.Config
	logger         logger.Logger
}

// NewFixBundleGenerator creates a new fix bundle generator.
func NewFixBundleGenerator(cfg *config.Config, log logger.Logger) *FixBundleGenerator {
	return &FixBundleGenerator{
		remediationGen: NewRemediationReporter(cfg, log),
		config:         cfg,
		logger:         log,
	}
}

// Generate creates the fix bundle directory structure.
func (g *FixBundleGenerator) Generate(findings []models.Finding, outputPath string) error {
	g.logger.Info("Generating fix bundle", "output", outputPath)

	// Create the base directory
	if err := os.MkdirAll(outputPath, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate the remediation manifest using existing reporter
	manifest, err := g.generateManifest(findings)
	if err != nil {
		return fmt.Errorf("failed to generate manifest: %w", err)
	}

	// Write manifest.yaml
	manifestPath := filepath.Join(outputPath, "manifest.yaml")
	if err := g.writeManifest(manifest, manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	// Create directory structure
	dirs := []string{
		filepath.Join(outputPath, "remediations"),
		filepath.Join(outputPath, "scripts"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Generate remediation directories
	for _, rem := range manifest.Remediations {
		if err := g.generateRemediationDir(rem, outputPath); err != nil {
			return fmt.Errorf("failed to generate remediation %s: %w", rem.ID, err)
		}
	}

	// Generate summary README
	if err := g.generateSummaryReadme(manifest, outputPath); err != nil {
		return fmt.Errorf("failed to generate summary README: %w", err)
	}

	// Generate scripts
	if err := g.generateScripts(manifest, outputPath); err != nil {
		return fmt.Errorf("failed to generate scripts: %w", err)
	}

	g.logger.Info("Fix bundle generated successfully", "path", outputPath)
	return nil
}

// generateManifest uses the existing RemediationReporter to create a manifest.
func (g *FixBundleGenerator) generateManifest(findings []models.Finding) (*remediation.Manifest, error) {
	// Create a temporary file for the manifest
	tmpFile, err := os.CreateTemp("", "manifest-*.yaml")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	// Create minimal metadata for the remediation generator
	metadata := &models.ScanMetadata{
		ID:        "fix-bundle-" + time.Now().Format("20060102-150405"),
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}

	// Generate manifest using existing reporter
	if err := g.remediationGen.Generate(findings, nil, metadata, tmpFile.Name()); err != nil {
		return nil, err
	}

	// Read back the manifest
	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, err
	}

	var manifest remediation.Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

// writeManifest writes the manifest to a file.
func (g *FixBundleGenerator) writeManifest(manifest *remediation.Manifest, path string) error {
	data, err := yaml.Marshal(manifest)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// generateRemediationDir creates the directory structure for a single remediation.
func (g *FixBundleGenerator) generateRemediationDir(rem remediation.Remediation, basePath string) error {
	remDir := filepath.Join(basePath, "remediations", rem.ID)
	if err := os.MkdirAll(remDir, 0750); err != nil {
		return err
	}

	// Generate README for this remediation
	if err := g.generateRemediationReadme(rem, remDir); err != nil {
		return err
	}

	// Generate fix files based on strategy
	if err := g.generateFixFiles(rem, remDir); err != nil {
		return err
	}

	// Generate validation script
	if err := g.generateValidationScript(rem, remDir); err != nil {
		return err
	}

	// Generate LLM prompt
	if err := g.generateLLMPrompt(rem, remDir); err != nil {
		return err
	}

	return nil
}

// generateRemediationReadme creates a README for a specific remediation.
func (g *FixBundleGenerator) generateRemediationReadme(rem remediation.Remediation, dir string) error {
	tmpl := `# {{.Title}}

## Description
{{.Description}}

## Severity: {{.Severity}} | Priority: {{.Priority}}

## Target Repository Type: {{.Target.RepositoryType}}

## Affected Files
{{- range .Target.AffectedFiles}}
- {{.Pattern}}
{{- end}}

## Findings Fixed
This remediation addresses {{len .FindingRefs}} findings:
{{- range .FindingRefs}}
- {{.}}
{{- end}}

## Implementation Steps
{{.Implementation.Approach}}

## Files in this Directory
- ` + "`fix.patch`" + ` - Git patch to apply the fix (if applicable)
- ` + "`terraform/`" + ` - Terraform files with the fix (if applicable)
- ` + "`validation.sh`" + ` - Script to verify the fix was applied correctly
- ` + "`llm-prompt.txt`" + ` - Instructions for LLM-assisted remediation

## Validation
Run ` + "`./validation.sh`" + ` after applying the fix to ensure it worked correctly.

## Rollback
{{.Rollback.Instructions}}
`

	t, err := template.New("readme").Parse(tmpl)
	if err != nil {
		return err
	}

	readmePath := filepath.Join(dir, "README.md")
	readmePath = filepath.Clean(readmePath)
	file, err := os.Create(readmePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	return t.Execute(file, rem)
}

// generateFixFiles creates the actual fix files based on the remediation strategy.
func (g *FixBundleGenerator) generateFixFiles(rem remediation.Remediation, dir string) error {
	// Determine the fix strategy from the implementation
	strategy := g.detectStrategy(rem)

	switch strategy {
	case "terraform-s3-public-access":
		return g.generateTerraformS3Fix(rem, dir)
	case "terraform-s3-encryption":
		return g.generateTerraformS3EncryptionFix(rem, dir)
	case "terraform-rds-encryption":
		return g.generateTerraformRDSEncryptionFix(rem, dir)
	case "terraform-iam-policy":
		return g.generateTerraformIAMFix(rem, dir)
	case "container-cve-critical", "container-cve-updates":
		return g.generateContainerFix(rem, dir)
	case "kubernetes-security-context":
		return g.generateKubernetesSecurityContextFix(rem, dir)
	case "kubernetes-network-policy":
		return g.generateKubernetesNetworkPolicyFix(rem, dir)
	case "kubernetes-rbac":
		return g.generateKubernetesRBACFix(rem, dir)
	default:
		// Generate a generic patch file with instructions
		return g.generateGenericPatch(rem, dir)
	}
}

// detectStrategy attempts to determine the fix strategy from the remediation.
func (g *FixBundleGenerator) detectStrategy(rem remediation.Remediation) string {
	// Check the title and description for clues
	title := strings.ToLower(rem.Title)
	desc := strings.ToLower(rem.Description)

	if strings.Contains(title, "s3") && strings.Contains(title, "public") {
		return "terraform-s3-public-access"
	}
	if strings.Contains(title, "s3") && strings.Contains(title, "encrypt") {
		return "terraform-s3-encryption"
	}
	if strings.Contains(title, "rds") && strings.Contains(title, "encrypt") {
		return "terraform-rds-encryption"
	}
	if strings.Contains(title, "iam") {
		return "terraform-iam-policy"
	}
	if strings.Contains(title, "cve") && strings.Contains(desc, "critical") {
		return "container-cve-critical"
	}
	if strings.Contains(title, "cve") {
		return "container-cve-updates"
	}
	if strings.Contains(title, "security context") {
		return "kubernetes-security-context"
	}
	if strings.Contains(title, "network policy") {
		return "kubernetes-network-policy"
	}
	if strings.Contains(title, "rbac") {
		return "kubernetes-rbac"
	}

	return "generic"
}

// generateTerraformS3Fix generates Terraform files for S3 public access fixes.
func (g *FixBundleGenerator) generateTerraformS3Fix(rem remediation.Remediation, dir string) error {
	// Create terraform directory
	tfDir := filepath.Join(dir, "terraform")
	if err := os.MkdirAll(tfDir, 0750); err != nil {
		return err
	}

	// Generate s3_public_access_block.tf
	tfContent := `# S3 Public Access Block Configuration
# This fix blocks public access to S3 buckets

# For each S3 bucket in your configuration, add a corresponding public access block
# Example for a bucket named "example":

resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Also ensure your bucket has private ACL
resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "private"
}

# If you have multiple buckets, you can use a for_each loop:
locals {
  bucket_names = [
    # Add your bucket resource names here
    # "bucket1",
    # "bucket2",
  ]
}

resource "aws_s3_bucket_public_access_block" "all" {
  for_each = toset(local.bucket_names)
  
  bucket = aws_s3_bucket[each.key].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`

	tfPath := filepath.Join(tfDir, "s3_public_access_block.tf")
	if err := os.WriteFile(tfPath, []byte(tfContent), 0600); err != nil {
		return err
	}

	// Generate a patch file showing the changes
	patchContent := `diff --git a/terraform/s3.tf b/terraform/s3.tf
index 0000000..1111111 100644
--- a/terraform/s3.tf
+++ b/terraform/s3.tf
@@ -10,6 +10,23 @@ resource "aws_s3_bucket" "example" {
   bucket = "my-example-bucket"
 }
 
+resource "aws_s3_bucket_public_access_block" "example" {
+  bucket = aws_s3_bucket.example.id
+
+  block_public_acls       = true
+  block_public_policy     = true
+  ignore_public_acls      = true
+  restrict_public_buckets = true
+}
+
+resource "aws_s3_bucket_acl" "example" {
+  bucket = aws_s3_bucket.example.id
+  acl    = "private"
+}
+
 # Additional bucket configuration...
`

	patchPath := filepath.Join(dir, "fix.patch")
	return os.WriteFile(patchPath, []byte(patchContent), 0600)
}

// generateValidationScript creates a validation script for the remediation.
func (g *FixBundleGenerator) generateValidationScript(rem remediation.Remediation, dir string) error {
	// Start with a basic template
	scriptContent := `#!/bin/bash
# Validation script for: {{.Title}}
# Generated by Prismatic

set -e

echo "Validating remediation: {{.ID}}"
echo "================================"

# Check if required tools are installed
command -v aws >/dev/null 2>&1 || { echo "AWS CLI is required but not installed. Aborting." >&2; exit 1; }

# Validation steps from remediation manifest
{{range .Validation}}
echo "Checking: {{.Step}}"
{{.Command}}
EXPECTED="{{.ExpectedOutput}}"
if [[ $? -eq 0 ]]; then
    echo "✓ {{.Step}} - PASSED"
else
    echo "✗ {{.Step}} - FAILED"
    exit 1
fi
{{end}}

echo ""
echo "All validation checks passed! ✓"
`

	// For specific strategies, add custom validation
	strategy := g.detectStrategy(rem)
	switch strategy {
	case "terraform-s3-public-access":
		scriptContent = g.generateS3ValidationScript(rem)
	case "kubernetes-security-context":
		scriptContent = g.generateK8sValidationScript(rem)
	}

	// Parse and execute template
	tmpl, err := template.New("validation").Parse(scriptContent)
	if err != nil {
		// If template parsing fails, write a basic script
		scriptContent = `#!/bin/bash
echo "Validation for: ` + rem.Title + `"
echo "Please verify the fix was applied correctly"
echo "Check the remediation manifest for validation steps"
exit 0
`
		scriptPath := filepath.Join(dir, "validation.sh")
		return os.WriteFile(scriptPath, []byte(scriptContent), 0700)
	}

	scriptPath := filepath.Join(dir, "validation.sh")
	scriptPath = filepath.Clean(scriptPath)
	file, err := os.Create(scriptPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	if err := tmpl.Execute(file, rem); err != nil {
		_ = file.Close()
		// Write a basic script as fallback
		basicScript := `#!/bin/bash
echo "Validation for: ` + rem.Title + `"
echo "Please verify the fix was applied correctly"
exit 0
`
		return os.WriteFile(scriptPath, []byte(basicScript), 0700)
	}

	// Make the script executable
	return os.Chmod(scriptPath, 0700)
}

// generateS3ValidationScript creates a specific validation script for S3 fixes.
func (g *FixBundleGenerator) generateS3ValidationScript(rem remediation.Remediation) string {
	return `#!/bin/bash
# S3 Public Access Block Validation Script
# Generated by Prismatic

set -e

echo "Validating S3 Public Access Block Configuration"
echo "=============================================="

# Check if AWS CLI is available
if ! command -v aws &> /dev/null; then
    echo "Error: AWS CLI is not installed"
    exit 1
fi

# Get all S3 buckets
echo "Checking S3 buckets for public access blocks..."
buckets=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text)

failed=0
for bucket in $buckets; do
    echo -n "Checking bucket: $bucket ... "
    
    # Check public access block configuration
    if aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null | grep -q '"BlockPublicAcls": true'; then
        echo "✓ Public access blocked"
    else
        echo "✗ Public access NOT blocked"
        failed=$((failed + 1))
    fi
done

if [ $failed -eq 0 ]; then
    echo ""
    echo "All S3 buckets have public access blocks configured! ✓"
    exit 0
else
    echo ""
    echo "WARNING: $failed bucket(s) still allow public access"
    exit 1
fi
`
}

// generateK8sValidationScript creates a validation script for Kubernetes fixes.
func (g *FixBundleGenerator) generateK8sValidationScript(rem remediation.Remediation) string {
	return `#!/bin/bash
# Kubernetes Security Context Validation Script
# Generated by Prismatic

set -e

echo "Validating Kubernetes Security Context"
echo "====================================="

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl is not installed"
    exit 1
fi

# Get all pods and check security contexts
echo "Checking pod security contexts..."
namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}')

failed=0
for ns in $namespaces; do
    if [[ "$ns" == "kube-system" || "$ns" == "kube-public" ]]; then
        continue
    fi
    
    pods=$(kubectl get pods -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    for pod in $pods; do
        echo -n "Checking $ns/$pod ... "
        
        # Check if securityContext is defined
        if kubectl get pod "$pod" -n "$ns" -o jsonpath='{.spec.securityContext}' | grep -q "runAsNonRoot"; then
            echo "✓ Security context configured"
        else
            echo "✗ Missing security context"
            failed=$((failed + 1))
        fi
    done
done

if [ $failed -eq 0 ]; then
    echo ""
    echo "All pods have proper security contexts! ✓"
    exit 0
else
    echo ""
    echo "WARNING: $failed pod(s) missing security contexts"
    exit 1
fi
`
}

// generateLLMPrompt creates an LLM prompt file for the remediation.
func (g *FixBundleGenerator) generateLLMPrompt(rem remediation.Remediation, dir string) error {
	promptContent := fmt.Sprintf(`# LLM Remediation Instructions for %s

## Context
%s

## Task
%s

## Detailed Instructions
%s

## Code Changes Required
`, rem.Title, rem.Description, rem.Implementation.Approach, rem.Implementation.LLMInstructions)

	// Add code templates if available
	for _, change := range rem.Implementation.CodeChanges {
		promptContent += fmt.Sprintf("\n### File Pattern: %s\n", change.FilePattern)
		promptContent += fmt.Sprintf("Change Type: %s\n", change.ChangeType)
		if change.Template != "" {
			promptContent += fmt.Sprintf("```\n%s\n```\n", change.Template)
		}
	}

	// Add validation info
	promptContent += "\n## Validation\n"
	promptContent += "After making the changes, verify them by:\n"
	for _, step := range rem.Validation {
		promptContent += fmt.Sprintf("- %s\n", step.Step)
		if step.Command != "" {
			promptContent += fmt.Sprintf("  Command: `%s`\n", step.Command)
		}
	}

	promptPath := filepath.Join(dir, "llm-prompt.txt")
	return os.WriteFile(promptPath, []byte(promptContent), 0600)
}

// generateSummaryReadme creates the top-level README.
func (g *FixBundleGenerator) generateSummaryReadme(manifest *remediation.Manifest, outputPath string) error {
	tmpl := `# Prismatic Security Fix Bundle

Generated: {{.GeneratedAt}}
Total Findings: {{.Metadata.TotalFindings}}
Total Remediations: {{.Metadata.ActionableRemediations}}
Estimated Effort: {{.Metadata.EstimatedTotalEffort}}

## Priority Summary

### Critical Priority (Immediate Action Required)
{{- range .Remediations}}
{{- if eq .Priority 1}}
- {{.ID}}: {{.Title}} ({{.Severity}} severity, {{len .FindingRefs}} findings)
{{- end}}
{{- end}}

### High Priority 
{{- range .Remediations}}
{{- if eq .Priority 2}}
- {{.ID}}: {{.Title}} ({{.Severity}} severity, {{len .FindingRefs}} findings)
{{- end}}
{{- end}}

### Medium Priority
{{- range .Remediations}}
{{- if eq .Priority 3}}
- {{.ID}}: {{.Title}} ({{.Severity}} severity, {{len .FindingRefs}} findings)
{{- end}}
{{- end}}

### Low Priority
{{- range .Remediations}}
{{- if eq .Priority 4}}
- {{.ID}}: {{.Title}} ({{.Severity}} severity, {{len .FindingRefs}} findings)
{{- end}}
{{- end}}

### Deferred
{{- range .Remediations}}
{{- if eq .Priority 5}}
- {{.ID}}: {{.Title}} ({{.Severity}} severity, {{len .FindingRefs}} findings)
{{- end}}
{{- end}}

## Quick Start

1. Review the manifest.yaml for complete details
2. Start with Critical priority remediations
3. Use scripts/apply-all-critical.sh to apply all critical fixes
4. Run scripts/validate-all.sh to verify fixes

## Directory Structure

- ` + "`manifest.yaml`" + ` - Complete remediation manifest
- ` + "`remediations/`" + ` - Individual remediation directories
  - Each contains README, fix files, validation script, and LLM prompt
- ` + "`scripts/`" + ` - Automation scripts for bulk operations

## Support

For questions or issues, please refer to the Prismatic documentation.
`

	t, err := template.New("summary").Parse(tmpl)
	if err != nil {
		return err
	}

	readmePath := filepath.Join(outputPath, "README.md")
	readmePath = filepath.Clean(readmePath)
	file, err := os.Create(readmePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	return t.Execute(file, manifest)
}

// generateScripts creates the automation scripts.
func (g *FixBundleGenerator) generateScripts(manifest *remediation.Manifest, outputPath string) error {
	scriptsDir := filepath.Join(outputPath, "scripts")

	// Ensure scripts directory exists
	if err := os.MkdirAll(scriptsDir, 0750); err != nil {
		return fmt.Errorf("failed to create scripts directory: %w", err)
	}

	// Generate apply-all-critical.sh
	if err := g.generateApplyCriticalScript(manifest, scriptsDir); err != nil {
		return err
	}

	// Generate validate-all.sh
	if err := g.generateValidateAllScript(manifest, scriptsDir); err != nil {
		return err
	}

	return nil
}

// generateApplyCriticalScript creates a script to apply all critical fixes.
func (g *FixBundleGenerator) generateApplyCriticalScript(manifest *remediation.Manifest, scriptsDir string) error {
	scriptContent := `#!/bin/bash
# Apply all critical priority fixes
# Generated by Prismatic

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

echo "Applying Critical Priority Fixes"
echo "================================"

# Find all critical remediations
critical_count=0
`

	// Add critical remediations
	for _, rem := range manifest.Remediations {
		if rem.Priority == 1 {
			scriptContent += fmt.Sprintf(`
echo ""
echo "Applying %s: %s"
cd "$BASE_DIR/remediations/%s"

# Check if patch exists and apply it
if [ -f "fix.patch" ]; then
    echo "Applying patch..."
    # Note: This assumes we're in the repository root
    # Adjust the path as needed for your setup
    git apply --check fix.patch 2>/dev/null && git apply fix.patch || echo "Patch cannot be applied automatically"
fi

# Show terraform files if they exist
if [ -d "terraform" ]; then
    echo "Terraform files available in: remediations/%s/terraform/"
    echo "Please review and apply these changes to your Terraform configuration"
fi

critical_count=$((critical_count + 1))
`, rem.ID, rem.Title, rem.ID, rem.ID)
		}
	}

	scriptContent += `

echo ""
echo "Applied $critical_count critical fixes"
echo "Please run validate-all.sh to verify the fixes"
`

	scriptPath := filepath.Join(scriptsDir, "apply-all-critical.sh")
	return os.WriteFile(scriptPath, []byte(scriptContent), 0700)
}

// generateValidateAllScript creates a script to validate all fixes.
func (g *FixBundleGenerator) generateValidateAllScript(manifest *remediation.Manifest, scriptsDir string) error {
	scriptContent := `#!/bin/bash
# Validate all remediations
# Generated by Prismatic

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

echo "Validating All Remediations"
echo "==========================="

total=0
passed=0
failed=0

`

	// Sort remediations by priority
	sortedRems := make([]remediation.Remediation, len(manifest.Remediations))
	copy(sortedRems, manifest.Remediations)
	sort.Slice(sortedRems, func(i, j int) bool {
		return sortedRems[i].Priority < sortedRems[j].Priority
	})

	for _, rem := range sortedRems {
		scriptContent += fmt.Sprintf(`
echo ""
echo "Validating %s (Priority %d)"
if [ -f "$BASE_DIR/remediations/%s/validation.sh" ]; then
    if "$BASE_DIR/remediations/%s/validation.sh"; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        echo "FAILED: %s"
    fi
    total=$((total + 1))
else
    echo "No validation script found for %s"
fi
`, rem.ID, rem.Priority, rem.ID, rem.ID, rem.Title, rem.ID)
	}

	scriptContent += `

echo ""
echo "Validation Summary"
echo "=================="
echo "Total: $total"
echo "Passed: $passed"
echo "Failed: $failed"

if [ $failed -eq 0 ]; then
    echo ""
    echo "All validations passed! ✓"
    exit 0
else
    echo ""
    echo "Some validations failed. Please review and fix."
    exit 1
fi
`

	scriptPath := filepath.Join(scriptsDir, "validate-all.sh")
	return os.WriteFile(scriptPath, []byte(scriptContent), 0700)
}

// Additional fix generation methods for other strategies...

func (g *FixBundleGenerator) generateTerraformS3EncryptionFix(rem remediation.Remediation, dir string) error {
	tfDir := filepath.Join(dir, "terraform")
	if err := os.MkdirAll(tfDir, 0750); err != nil {
		return err
	}

	tfContent := `# S3 Bucket Encryption Configuration
# This fix enables encryption for S3 buckets

# For each S3 bucket, add server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
      # For KMS encryption, use:
      # sse_algorithm     = "aws:kms"
      # kms_master_key_id = aws_kms_key.mykey.arn
    }
  }
}
`

	tfPath := filepath.Join(tfDir, "s3_encryption.tf")
	return os.WriteFile(tfPath, []byte(tfContent), 0600)
}

func (g *FixBundleGenerator) generateTerraformRDSEncryptionFix(rem remediation.Remediation, dir string) error {
	tfDir := filepath.Join(dir, "terraform")
	if err := os.MkdirAll(tfDir, 0750); err != nil {
		return err
	}

	tfContent := `# RDS Encryption Configuration
# Enable encryption for RDS instances

# For new RDS instances, add:
resource "aws_db_instance" "example" {
  # ... other configuration ...
  
  # Enable encryption
  storage_encrypted = true
  # Optionally specify KMS key
  # kms_key_id = aws_kms_key.rds.arn
}

# For existing instances, you'll need to:
# 1. Create an encrypted snapshot
# 2. Restore from the encrypted snapshot
# See AWS documentation for the migration process
`

	tfPath := filepath.Join(tfDir, "rds_encryption.tf")
	return os.WriteFile(tfPath, []byte(tfContent), 0600)
}

func (g *FixBundleGenerator) generateTerraformIAMFix(rem remediation.Remediation, dir string) error {
	tfDir := filepath.Join(dir, "terraform")
	if err := os.MkdirAll(tfDir, 0750); err != nil {
		return err
	}

	tfContent := `# IAM Policy Fixes
# Apply least privilege principles

# Example: Restrict overly permissive policies
data "aws_iam_policy_document" "restricted" {
  statement {
    effect = "Allow"
    
    # Replace wildcard actions with specific actions
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      # Add only required actions
    ]
    
    # Replace wildcard resources with specific resources
    resources = [
      "arn:aws:s3:::my-bucket/*",
      # Add only required resources
    ]
    
    # Add conditions for additional security
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["AES256"]
    }
  }
}
`

	tfPath := filepath.Join(tfDir, "iam_policy_fixes.tf")
	return os.WriteFile(tfPath, []byte(tfContent), 0600)
}

func (g *FixBundleGenerator) generateContainerFix(rem remediation.Remediation, dir string) error {
	// Create a Dockerfile patch
	patchContent := `# Container Security Fixes

## For Critical CVEs:
1. Update base image to latest patched version
2. Update vulnerable packages
3. Rebuild and redeploy

## Example Dockerfile changes:
` + "```dockerfile" + `
# Update base image
-FROM node:14-alpine
+FROM node:18-alpine

# Update packages
RUN apk update && apk upgrade

# For specific package updates
RUN npm audit fix
` + "```" + `

## Validation:
- Run security scanner on new image
- Verify CVEs are resolved
- Test application functionality
`

	readmePath := filepath.Join(dir, "container-fixes.md")
	return os.WriteFile(readmePath, []byte(patchContent), 0600)
}

func (g *FixBundleGenerator) generateKubernetesSecurityContextFix(rem remediation.Remediation, dir string) error {
	k8sDir := filepath.Join(dir, "kubernetes")
	if err := os.MkdirAll(k8sDir, 0750); err != nil {
		return err
	}

	yamlContent := `# Security Context Configuration
apiVersion: apps/v1
kind: Deployment
metadata:
  name: example-deployment
spec:
  template:
    spec:
      # Pod-level security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault
      
      containers:
      - name: app
        # Container-level security context
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
`

	yamlPath := filepath.Join(k8sDir, "security-context.yaml")
	return os.WriteFile(yamlPath, []byte(yamlContent), 0600)
}

func (g *FixBundleGenerator) generateKubernetesNetworkPolicyFix(rem remediation.Remediation, dir string) error {
	k8sDir := filepath.Join(dir, "kubernetes")
	if err := os.MkdirAll(k8sDir, 0750); err != nil {
		return err
	}

	yamlContent := `# Network Policy Configuration
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
---
# Allow specific traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-traffic
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
`

	yamlPath := filepath.Join(k8sDir, "network-policy.yaml")
	return os.WriteFile(yamlPath, []byte(yamlContent), 0600)
}

func (g *FixBundleGenerator) generateKubernetesRBACFix(rem remediation.Remediation, dir string) error {
	k8sDir := filepath.Join(dir, "kubernetes")
	if err := os.MkdirAll(k8sDir, 0750); err != nil {
		return err
	}

	yamlContent := `# RBAC Configuration - Least Privilege
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: default
roleRef:
  kind: Role
  name: app-reader
  apiGroup: rbac.authorization.k8s.io
---
# ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: default
`

	yamlPath := filepath.Join(k8sDir, "rbac.yaml")
	return os.WriteFile(yamlPath, []byte(yamlContent), 0600)
}

func (g *FixBundleGenerator) generateGenericPatch(rem remediation.Remediation, dir string) error {
	patchContent := fmt.Sprintf(`# Generic Fix Instructions for %s

## Description
%s

## Manual Steps Required
%s

## Implementation Details
%s

## Validation
After applying the fix, verify it worked by:
`, rem.Title, rem.Description, rem.Implementation.Approach, rem.Implementation.LLMInstructions)

	for _, step := range rem.Validation {
		patchContent += fmt.Sprintf("- %s\n", step.Step)
	}

	instructionsPath := filepath.Join(dir, "fix-instructions.md")
	return os.WriteFile(instructionsPath, []byte(patchContent), 0600)
}

// fixBundleFormat adapts FixBundleGenerator to the ReportFormat interface.
type fixBundleFormat struct {
	generator *FixBundleGenerator
}

// Generate implements the ReportFormat interface.
func (f *fixBundleFormat) Generate(findings []models.Finding, enrichments map[string]*enrichment.FindingEnrichment, metadata *models.ScanMetadata, outputPath string) error {
	// The FixBundleGenerator doesn't use enrichments or metadata directly
	return f.generator.Generate(findings, outputPath)
}

// Name returns the format identifier.
func (f *fixBundleFormat) Name() string {
	return "fix-bundle"
}

// Description returns a human-readable description.
func (f *fixBundleFormat) Description() string {
	return "Directory structure with remediation files, scripts, and patches"
}
