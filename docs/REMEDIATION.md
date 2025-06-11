# Prismatic Remediation Report Format Design

## Overview

The remediation report format transforms security findings into actionable, machine-readable outputs that can be executed by developers, automation tools, or LLMs. This document describes new report formats that generate remediation manifests and fix bundles from enriched security findings.

## Implementation Status

✅ **Completed Features:**
- Remediation manifest generator (`--format remediation`)
- Fix bundle generator (`--format fix-bundle`)
- Finding grouper with intelligent fix strategies
- Validation script generation
- LLM prompt generation
- Summary scripts for bulk operations

🚧 **Not Yet Implemented:**
- GitHub issues format (`--format github-issues`)
- Interactive report generation
- IDE integrations
- Remediation tracking

## Motivation

While PDF/HTML reports are excellent for human review and compliance, modern DevSecOps workflows require:
- Machine-actionable remediation instructions
- LLM-ready task definitions for assisted fixing
- Integration with IaC repositories and GitOps workflows
- Validation and rollback procedures
- Prioritized, contextual fix strategies

## Architecture

### Report Format Extensions

```
┌──────┐     ┌─────────┐     ┌────────┐
│ SCAN │ --> │ ENRICH  │ --> │ REPORT │
└──────┘     └─────────┘     └────────┘
                                  ↓
                          Report Formats:
                          ├── html (human review)
                          ├── pdf (compliance)
                          ├── remediation (YAML manifest)
                          ├── fix-bundle (complete package)
                          └── github-issues (task tracking)
```

### Command Structure

```bash
# Generate traditional HTML report
prismatic report -s data/scans/latest --format html -o report.html

# Generate remediation manifest
prismatic report -s data/scans/latest --format remediation -o fixes.yaml

# Generate complete fix bundle
prismatic report -s data/scans/latest --format fix-bundle -o fix-bundle/

# Generate multiple formats from same scan
prismatic report -s data/scans/latest \
  --format html -o report.html \
  --format remediation -o fixes.yaml

# Filter what goes into remediation outputs
prismatic report -s data/scans/latest \
  --format remediation \
  --severity critical \
  --repos terraform \
  -o critical-fixes.yaml
```

## Data Formats

### Remediation Manifest Schema

```yaml
manifest_version: "1.0"
generated_at: "2024-01-15T14:30:00Z"
scan_id: "2024-01-15-133214"
metadata:
  total_findings: 47
  actionable_remediations: 23
  estimated_total_effort: "8 hours"
  priority_score: 9.2
  
remediations:
  - id: "rem-001"
    title: "Disable public access on S3 buckets"
    description: "Multiple S3 buckets expose sensitive data publicly"
    severity: "CRITICAL"
    priority: 1
    
    # Links to original findings
    finding_refs: ["s3-001", "s3-002", "s3-003"]
    
    # Where to apply the fix
    target:
      repository_type: "terraform"  # terraform, kubernetes, cloudformation, ansible
      repository_hints:
        - path: "infrastructure/"
        - path: "terraform/"
      affected_files:
        - pattern: "**/s3.tf"
        - pattern: "modules/storage/*.tf"
    
    # Context from enrichment
    context:
      business_impact: "Customer PII exposed, PCI compliance violation"
      data_at_risk: "2.3TB of user uploads, 5TB of backups"
      compliance_violations: ["PCI-DSS 3.4", "HIPAA 164.312(a)(1)"]
      exploitation_likelihood: "High - public S3 scanners active"
    
    # How to implement the fix
    implementation:
      approach: "Add bucket ACLs and public access blocks"
      estimated_effort: "30 minutes"
      requires_downtime: false
      
      # For LLM consumption
      llm_instructions: |
        Locate all aws_s3_bucket resources and:
        1. Set acl = "private" 
        2. Add corresponding aws_s3_bucket_public_access_block resources
        3. Ensure all four block settings are true
        
      # Specific code changes
      code_changes:
        - file_pattern: "**/s3.tf"
          change_type: "add_resource"
          description: "Add public access block for each bucket"
          template: |
            resource "aws_s3_bucket_public_access_block" "{{ bucket_name }}" {
              bucket = aws_s3_bucket.{{ bucket_name }}.id
              
              block_public_acls       = true
              block_public_policy     = true
              ignore_public_acls      = true
              restrict_public_buckets = true
            }
            
    # How to verify the fix worked
    validation:
      - step: "Check bucket ACL"
        command: "aws s3api get-bucket-acl --bucket {{ bucket_name }}"
        expected_output: "No public-read grants"
        
      - step: "Verify public access block"
        command: "aws s3api get-public-access-block --bucket {{ bucket_name }}"
        expected_output: "All settings true"
        
      - step: "Test public access"
        command: "curl -I https://{{ bucket_name }}.s3.amazonaws.com/test.txt"
        expected_output: "403 Forbidden"
    
    # How to undo if needed
    rollback:
      instructions: "Remove public access block resources and revert ACL changes"
      risk: "None - this change only restricts access"
      
    # Dependencies and ordering
    dependencies: []
    blocks: ["rem-005"]  # Don't do rem-005 until this is complete
```

### Fix Bundle Structure

```
fix-bundle/
├── manifest.yaml                    # Complete remediation manifest
├── README.md                        # Human-readable overview
├── priorities.md                    # Ordered task list with effort estimates
│
├── remediations/
│   ├── rem-001-s3-public-access/
│   │   ├── README.md               # Specific instructions for this fix
│   │   ├── fix.patch               # Git patch file (if applicable)
│   │   ├── terraform/
│   │   │   └── s3_public_access_block.tf
│   │   ├── validation.sh           # Script to verify fix
│   │   └── llm-prompt.txt          # Ready-to-use LLM prompt
│   │
│   └── rem-002-cve-patches/
│       ├── README.md
│       ├── kubernetes/
│       │   └── patches/
│       │       └── api-gateway-patch.yaml
│       └── docker/
│           └── Dockerfile.patch
│
├── scripts/
│   ├── apply-all-critical.sh       # Batch apply critical fixes
│   ├── validate-all.sh             # Run all validations
│   └── generate-prs.sh             # Create PRs for each fix
│
└── reports/
    ├── impact-analysis.md          # What happens if fixes aren't applied
    └── compliance-mapping.md       # Which fixes address which compliance requirements
```

## Implementation

### Current Architecture

The remediation system is implemented across several packages:

```
internal/
├── remediation/           # Core remediation logic
│   ├── types.go          # Data structures (Manifest, Remediation, etc.)
│   └── grouper.go        # Finding grouping and fix strategies
└── report/               # Report generation
    ├── remediation.go    # YAML manifest generator
    └── fix_bundle.go     # Fix bundle directory generator
```

### Integration with Report Package

```go
// internal/report/formats.go - Actual implementation
func init() {
    // HTML format registration
    RegisterFormat("html", func(cfg *config.Config, log logger.Logger) (ReportFormat, error) {
        return NewHTMLGenerator(cfg, log), nil
    })
    
    // Remediation manifest format
    RegisterFormat("remediation", func(cfg *config.Config, log logger.Logger) (ReportFormat, error) {
        return NewRemediationReporter(cfg, log), nil
    })
    
    // Fix bundle format
    RegisterFormat("fix-bundle", func(cfg *config.Config, log logger.Logger) (ReportFormat, error) {
        return &fixBundleFormat{
            generator: NewFixBundleGenerator(cfg, log),
        }, nil
    })
}

// internal/report/remediation.go - Actual implementation
type RemediationReporter struct {
    config  *config.Config
    logger  logger.Logger
    grouper *remediation.FindingGrouper
}

func (r *RemediationReporter) Generate(findings []models.Finding, outputPath string) error {
    // Filter suppressed findings
    activeFindings := r.filterActiveFindings(findings)
    
    // Group findings by fix strategy
    groups := r.grouper.GroupFindings(activeFindings)
    
    // Create manifest with metadata
    manifest := &remediation.Manifest{
        ManifestVersion: "1.0",
        GeneratedAt:     time.Now().Format(time.RFC3339),
        Metadata:        r.createMetadata(activeFindings, groups),
        Remediations:    []remediation.Remediation{},
    }
    
    // Generate remediations from groups
    for _, group := range groups {
        rem := r.createRemediation(group)
        manifest.Remediations = append(manifest.Remediations, rem)
    }
    
    // Sort by priority
    sort.Slice(manifest.Remediations, func(i, j int) bool {
        return manifest.Remediations[i].Priority < manifest.Remediations[j].Priority
    })
    
    // Write YAML output
    return r.writeYAML(manifest, outputPath)
}
```

### Fix Strategies (Actual Implementation)

```go
// internal/remediation/grouper.go - Strategy determination
func (g *FindingGrouper) determineStrategy(finding models.Finding) string {
    switch finding.Scanner {
    case "prowler":
        return g.determineProwlerStrategy(finding)
    case "trivy":
        return g.determineTrivyStrategy(finding)
    case "kubescape":
        return g.determineKubescapeStrategy(finding)
    // ... other scanners
    }
    return "generic"
}

// Example: Prowler S3 strategies
func (g *FindingGrouper) determineProwlerStrategy(finding models.Finding) string {
    findingType := strings.ToLower(finding.Type)
    
    // S3 related
    if strings.Contains(findingType, "s3") {
        if strings.Contains(findingType, "public") || strings.Contains(findingType, "acl") {
            return "terraform-s3-public-access"
        }
        if strings.Contains(findingType, "encrypt") {
            return "terraform-s3-encryption"
        }
    }
    // ... other strategies
}

// Fix bundle generator applies strategies
// internal/report/fix_bundle.go
func (g *FixBundleGenerator) generateFixFiles(rem remediation.Remediation, dir string) error {
    strategy := g.detectStrategy(rem)
    
    switch strategy {
    case "terraform-s3-public-access":
        return g.generateTerraformS3Fix(rem, dir)
    case "kubernetes-security-context":
        return g.generateKubernetesSecurityContextFix(rem, dir)
    // ... other strategies
    }
}
```

### LLM Integration (Actual Implementation)

```go
// internal/report/fix_bundle.go - LLM prompt generation
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
    
    // Save to file
    promptPath := filepath.Join(dir, "llm-prompt.txt")
    return os.WriteFile(promptPath, []byte(promptContent), 0644)
}
```

## Usage Examples

### Example 1: Generate Terraform Fixes

```bash
# Scan and enrich
prismatic scan -c prod.yaml
prismatic enrich -s data/scans/latest

# Generate remediation manifest
prismatic report -s data/scans/latest --format remediation -o fixes.yaml

# In terraform repo
cd ~/repos/infrastructure
claude -p "$(cat ~/prismatic/fixes.yaml | yq '.remediations[0].implementation.llm_instructions')"
```

### Example 2: Automated Fix Bundle

```bash
# Generate complete fix bundle
prismatic report -s data/scans/latest --format fix-bundle -o ~/fix-bundle/

# Review generated structure
$ tree ~/fix-bundle/
fix-bundle/
├── manifest.yaml
├── README.md
├── remediations/
│   ├── rem-001-s3-public-access/
│   │   ├── README.md
│   │   ├── fix.patch
│   │   ├── terraform/
│   │   │   └── s3_public_access_block.tf
│   │   ├── validation.sh
│   │   └── llm-prompt.txt
│   └── rem-002-.../
├── scripts/
│   ├── apply-all-critical.sh
│   └── validate-all.sh

# Apply critical fixes
cd ~/repos/infrastructure
~/fix-bundle/scripts/apply-all-critical.sh

# Validate
~/fix-bundle/scripts/validate-all.sh
```

### Example 3: Multiple Output Formats

```bash
# Generate all report types from one scan
prismatic report \
  -s data/scans/latest \
  --format html -o report.html \
  --format remediation -o fixes.yaml \
  --format fix-bundle -o fix-bundle/
  
# Or generate specific severity fixes only
prismatic report \
  -s data/scans/latest \
  --format remediation \
  --severity critical \
  -o critical-fixes.yaml
```

## Testing Strategy

### Unit Tests

```go
func TestRemediationGrouping(t *testing.T) {
    findings := []models.EnrichedFinding{
        // 10 S3 findings
        // 5 RDS findings  
        // 3 IAM findings
    }
    
    generator := NewRemediationGenerator(findings, config)
    manifest := generator.GenerateManifest()
    
    // Should create 3 remediation groups
    assert.Equal(t, 3, len(manifest.Remediations))
    
    // S3 remediation should reference all 10 findings
    s3Rem := manifest.Remediations[0]
    assert.Equal(t, 10, len(s3Rem.FindingRefs))
}

func TestLLMPromptGeneration(t *testing.T) {
    rem := Remediation{
        Title: "Fix S3 public access",
        Target: RemediationTarget{
            RepositoryType: "terraform",
        },
    }
    
    prompt := generator.GeneratePrompt(rem)
    
    // Should include key sections
    assert.Contains(t, prompt, "terraform repository")
    assert.Contains(t, prompt, "Fix S3 public access")
    assert.Contains(t, prompt, "SUCCESS CRITERIA")
}
```

### Integration Tests

```go
func TestFixBundleGeneration(t *testing.T) {
    // Create test scan with findings
    scanPath := createTestScan(t)
    
    // Generate fix bundle using report command
    cmd := exec.Command("prismatic", "report", 
        "-s", scanPath,
        "--format", "fix-bundle",
        "-o", t.TempDir())
    
    err := cmd.Run()
    assert.NoError(t, err)
    
    // Verify structure
    assert.FileExists(t, "manifest.yaml")
    assert.DirExists(t, "remediations")
    assert.FileExists(t, "scripts/validate-all.sh")
}
```

## Configuration

```yaml
# configs/client.yaml
report:
  # Existing HTML/PDF configuration
  branding:
    company_name: "Example Corp"
    logo_path: "assets/logo.png"
    
  # Remediation report configuration
  remediation:
    # Grouping strategy
    grouping:
      by: ["repository_type", "service", "severity"]
      max_per_group: 20
    
    # Repository detection
    repositories:
      terraform:
        patterns: ["*.tf", "terraform/", "infrastructure/"]
        root_indicators: [".terraform", "terraform.tfstate"]
      kubernetes:
        patterns: ["*.yaml", "k8s/", "manifests/"]
        root_indicators: ["kustomization.yaml", ".flux.yaml"]
    
    # Output preferences  
    output:
      include_llm_prompts: true
      include_validation_scripts: true
      include_rollback_procedures: true
      
    # Filtering
    filters:
      min_severity: "LOW"
      exclude_scanners: []
      include_only_actionable: true
```

## Future Enhancements

### 1. Interactive Report Generation
```bash
prismatic report --interactive
> Found 47 findings. Generate report? [Y/n]
> Select formats (space to select, enter to confirm):
  [x] HTML report
  [ ] PDF report
  [x] Remediation manifest
  [ ] Fix bundle
> Filter remediations by severity? [All/Critical/High]
```

### 2. IDE Integration
- VS Code extension that reads manifests
- IntelliJ plugin for applying fixes
- GitHub Copilot integration

### 3. Remediation Tracking
```go
type RemediationStatus struct {
    ID          string
    Applied     bool
    AppliedAt   time.Time
    AppliedBy   string
    Validated   bool
    PRLink      string
}
```

### 4. Smart Fix Ordering
- Dependency analysis between fixes
- Risk-based prioritization
- Effort optimization (batch similar fixes)

## Success Metrics

1. **Actionability**: >90% of remediations can be applied without modification
2. **LLM Success Rate**: >80% of LLM-applied fixes pass validation
3. **Time to Fix**: 50% reduction in remediation time
4. **Coverage**: Remediation strategies for >95% of finding types

---

This design enables Prismatic to bridge the gap between security findings and actual fixes, making remediation a seamless part of the DevSecOps workflow.