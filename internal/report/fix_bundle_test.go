package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/remediation"
	"github.com/joshsymonds/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFixBundleGenerator(t *testing.T) {
	log := logger.NewMockLogger()

	gen := NewFixBundleGenerator(log)

	assert.NotNil(t, gen)
	assert.NotNil(t, gen.remediationGen)
	assert.Equal(t, log, gen.logger)
}

func TestFixBundleGenerator_Generate(t *testing.T) {
	// Create a temporary directory for output
	tmpDir, err := os.MkdirTemp("", "fix-bundle-test-*")
	require.NoError(t, err)
	defer func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			t.Errorf("Failed to remove temp dir: %v", removeErr)
		}
	}()

	// Create test findings
	findings := []models.Finding{
		{
			ID:          "finding-1",
			Scanner:     "prowler",
			Type:        "s3_bucket_public_read_access",
			Severity:    models.SeverityCritical,
			Title:       "S3 Bucket allows public read access",
			Description: "S3 bucket 'test-bucket' allows public read access",
			Resource:    "test-bucket",
		},
		{
			ID:          "finding-2",
			Scanner:     "prowler",
			Type:        "s3_bucket_public_write_access",
			Severity:    models.SeverityHigh,
			Title:       "S3 Bucket allows public write access",
			Description: "S3 bucket 'test-bucket' allows public write access",
			Resource:    "test-bucket",
		},
	}

	log := logger.NewMockLogger()
	gen := NewFixBundleGenerator(log)

	// Generate the fix bundle
	err = gen.Generate(findings, tmpDir)
	require.NoError(t, err)

	// Verify directory structure
	assert.DirExists(t, filepath.Join(tmpDir, "remediations"))
	assert.DirExists(t, filepath.Join(tmpDir, "scripts"))

	// Verify files exist
	assert.FileExists(t, filepath.Join(tmpDir, "manifest.json"))
	assert.FileExists(t, filepath.Join(tmpDir, "README.md"))
	assert.FileExists(t, filepath.Join(tmpDir, "scripts", "apply-all-critical.sh"))
	assert.FileExists(t, filepath.Join(tmpDir, "scripts", "validate-all.sh"))

	// Check script permissions
	info, err := os.Stat(filepath.Join(tmpDir, "scripts", "apply-all-critical.sh"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())

	info, err = os.Stat(filepath.Join(tmpDir, "scripts", "validate-all.sh"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
}

func TestFixBundleGenerator_detectStrategy(t *testing.T) {
	gen := &FixBundleGenerator{}

	tests := []struct {
		name     string
		expected string
		rem      remediation.Remediation
	}{
		{
			name: "S3 public access",
			rem: remediation.Remediation{
				Title:       "Fix S3 Public Access",
				Description: "Block public access to S3 buckets",
			},
			expected: "terraform-s3-public-access",
		},
		{
			name: "S3 encryption",
			rem: remediation.Remediation{
				Title:       "Enable S3 Encryption",
				Description: "Enable encryption for S3 buckets",
			},
			expected: "terraform-s3-encryption",
		},
		{
			name: "RDS encryption",
			rem: remediation.Remediation{
				Title:       "Enable RDS Encryption",
				Description: "Enable encryption for RDS instances",
			},
			expected: "terraform-rds-encryption",
		},
		{
			name: "IAM policy",
			rem: remediation.Remediation{
				Title:       "Fix IAM Policy",
				Description: "Apply least privilege to IAM policies",
			},
			expected: "terraform-iam-policy",
		},
		{
			name: "Critical CVE",
			rem: remediation.Remediation{
				Title:       "Fix CVE-2023-1234",
				Description: "Critical vulnerability in container image",
			},
			expected: "container-cve-critical",
		},
		{
			name: "Security context",
			rem: remediation.Remediation{
				Title:       "Add Security Context",
				Description: "Configure pod security context",
			},
			expected: "kubernetes-security-context",
		},
		{
			name: "Network policy",
			rem: remediation.Remediation{
				Title:       "Configure Network Policy",
				Description: "Add network policies to restrict traffic",
			},
			expected: "kubernetes-network-policy",
		},
		{
			name: "RBAC",
			rem: remediation.Remediation{
				Title:       "Fix RBAC Configuration",
				Description: "Apply least privilege RBAC",
			},
			expected: "kubernetes-rbac",
		},
		{
			name: "Generic",
			rem: remediation.Remediation{
				Title:       "Generic Security Issue",
				Description: "Some other security issue",
			},
			expected: "generic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gen.detectStrategy(tt.rem)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFixBundleGenerator_generateRemediationDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "remediation-dir-test-*")
	require.NoError(t, err)
	defer func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			t.Errorf("Failed to remove temp dir: %v", removeErr)
		}
	}()

	gen := &FixBundleGenerator{
		logger: logger.NewMockLogger(),
	}

	rem := remediation.Remediation{
		ID:          "rem-001",
		Title:       "Fix S3 Public Access",
		Description: "Block public access to S3 buckets",
		Severity:    models.SeverityCritical,
		Priority:    1,
		FindingRefs: []string{"finding-1", "finding-2"},
		Target: remediation.Target{
			RepositoryType: remediation.RepoTypeTerraform,
		},
		Implementation: remediation.Implementation{
			Approach:        "Add public access blocks",
			LLMInstructions: "Configure S3 bucket public access blocks",
			CodeChanges: []remediation.CodeChange{
				{
					FilePattern: "**/*.tf",
					ChangeType:  "add_resource",
					Template:    "resource template here",
				},
			},
		},
		Validation: []remediation.ValidationStep{
			{
				Step:           "Check public access block",
				Command:        "aws s3api get-public-access-block --bucket test-bucket",
				ExpectedOutput: "BlockPublicAcls: true",
			},
		},
		Rollback: remediation.RollbackProcedure{
			Instructions: "Remove public access blocks",
			Risk:         "Low",
		},
	}

	err = gen.generateRemediationDir(rem, tmpDir)
	require.NoError(t, err)

	// Verify directory structure
	remDir := filepath.Join(tmpDir, "remediations", "rem-001")
	assert.DirExists(t, remDir)

	// Verify files
	assert.FileExists(t, filepath.Join(remDir, "README.md"))
	assert.FileExists(t, filepath.Join(remDir, "validation.sh"))
	assert.FileExists(t, filepath.Join(remDir, "llm-prompt.txt"))

	// Check validation script is executable
	info, err := os.Stat(filepath.Join(remDir, "validation.sh"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())

	// Verify README content
	// #nosec G304 -- remDir is constructed safely from test inputs
	readmeContent, err := os.ReadFile(filepath.Join(remDir, "README.md"))
	require.NoError(t, err)
	assert.Contains(t, string(readmeContent), "Fix S3 Public Access")
	assert.Contains(t, string(readmeContent), "critical")
	assert.Contains(t, string(readmeContent), "finding-1")
	assert.Contains(t, string(readmeContent), "finding-2")
}

func TestFixBundleGenerator_generateTerraformS3Fix(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "terraform-s3-test-*")
	require.NoError(t, err)
	defer func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			t.Errorf("Failed to remove temp dir: %v", removeErr)
		}
	}()

	gen := &FixBundleGenerator{
		logger: logger.NewMockLogger(),
	}

	rem := remediation.Remediation{
		ID:    "rem-001",
		Title: "Fix S3 Public Access",
	}

	err = gen.generateTerraformS3Fix(rem, tmpDir)
	require.NoError(t, err)

	// Verify terraform directory and files
	tfDir := filepath.Join(tmpDir, "terraform")
	assert.DirExists(t, tfDir)
	assert.FileExists(t, filepath.Join(tfDir, "s3_public_access_block.tf"))
	assert.FileExists(t, filepath.Join(tmpDir, "fix.patch"))

	// Check terraform file content
	// #nosec G304 -- tfDir is constructed safely from test inputs
	tfContent, err := os.ReadFile(filepath.Join(tfDir, "s3_public_access_block.tf"))
	require.NoError(t, err)
	assert.Contains(t, string(tfContent), "aws_s3_bucket_public_access_block")
	assert.Contains(t, string(tfContent), "block_public_acls       = true")
	assert.Contains(t, string(tfContent), "block_public_policy     = true")
	assert.Contains(t, string(tfContent), "ignore_public_acls      = true")
	assert.Contains(t, string(tfContent), "restrict_public_buckets = true")
}

func TestFixBundleGenerator_generateValidationScript(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "validation-test-*")
	require.NoError(t, err)
	defer func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			t.Errorf("Failed to remove temp dir: %v", removeErr)
		}
	}()

	gen := &FixBundleGenerator{
		logger: logger.NewMockLogger(),
	}

	tests := []struct {
		name         string
		checkContent []string
		rem          remediation.Remediation
	}{
		{
			name: "S3 validation",
			rem: remediation.Remediation{
				ID:    "rem-001",
				Title: "Fix S3 Public Access",
				Validation: []remediation.ValidationStep{
					{
						Step:           "Check public access block",
						Command:        "aws s3api get-public-access-block --bucket test",
						ExpectedOutput: "BlockPublicAcls: true",
					},
				},
			},
			checkContent: []string{
				"S3 Public Access Block Validation",
				"aws s3api get-public-access-block",
			},
		},
		{
			name: "Kubernetes validation",
			rem: remediation.Remediation{
				ID:    "rem-002",
				Title: "Add Security Context",
				Validation: []remediation.ValidationStep{
					{
						Step:    "Check security context",
						Command: "kubectl get pods -o yaml",
					},
				},
			},
			checkContent: []string{
				"Kubernetes Security Context Validation",
				"kubectl get pods",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDir := filepath.Join(tmpDir, tt.name)
			require.NoError(t, os.MkdirAll(testDir, 0750))

			err := gen.generateValidationScript(tt.rem, testDir)
			require.NoError(t, err)

			scriptPath := filepath.Join(testDir, "validation.sh")
			assert.FileExists(t, scriptPath)

			// Check permissions
			info, err := os.Stat(scriptPath)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0755), info.Mode().Perm())

			// Check content
			// #nosec G304 -- scriptPath is constructed safely from test inputs
			content, err := os.ReadFile(scriptPath)
			require.NoError(t, err)
			for _, check := range tt.checkContent {
				assert.Contains(t, string(content), check)
			}
		})
	}
}

func TestFixBundleGenerator_generateLLMPrompt(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "llm-prompt-test-*")
	require.NoError(t, err)
	defer func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			t.Errorf("Failed to remove temp dir: %v", removeErr)
		}
	}()

	gen := &FixBundleGenerator{
		logger: logger.NewMockLogger(),
	}

	rem := remediation.Remediation{
		ID:          "rem-001",
		Title:       "Fix S3 Public Access",
		Description: "Block public access to S3 buckets",
		Implementation: remediation.Implementation{
			Approach:        "Add public access blocks",
			LLMInstructions: "Configure S3 bucket public access blocks for all buckets",
			CodeChanges: []remediation.CodeChange{
				{
					FilePattern: "**/*.tf",
					ChangeType:  "add_resource",
					Template:    "resource \"aws_s3_bucket_public_access_block\" ...",
				},
			},
		},
		Validation: []remediation.ValidationStep{
			{
				Step:    "Check public access block",
				Command: "aws s3api get-public-access-block --bucket test",
			},
		},
	}

	err = gen.generateLLMPrompt(rem, tmpDir)
	require.NoError(t, err)

	promptPath := filepath.Join(tmpDir, "llm-prompt.txt")
	assert.FileExists(t, promptPath)

	// #nosec G304 -- promptPath is constructed safely from test inputs
	content, err := os.ReadFile(promptPath)
	require.NoError(t, err)

	// Check content includes all sections
	contentStr := string(content)
	assert.Contains(t, contentStr, "Fix S3 Public Access")
	assert.Contains(t, contentStr, "Block public access to S3 buckets")
	assert.Contains(t, contentStr, "Configure S3 bucket public access blocks")
	assert.Contains(t, contentStr, "**/*.tf")
	assert.Contains(t, contentStr, "Check public access block")
}

func TestFixBundleGenerator_generateSummaryReadme(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "summary-test-*")
	require.NoError(t, err)
	defer func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			t.Errorf("Failed to remove temp dir: %v", removeErr)
		}
	}()

	gen := &FixBundleGenerator{
		logger: logger.NewMockLogger(),
	}

	manifest := &remediation.Manifest{
		ManifestVersion: "1.0",
		GeneratedAt:     time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Metadata: remediation.ManifestMetadata{
			TotalFindings:          10,
			ActionableRemediations: 3,
			EstimatedTotalEffort:   "4 hours",
			PriorityScore:          8.5,
		},
		Remediations: []remediation.Remediation{
			{
				ID:          "rem-001",
				Title:       "Critical Fix",
				Severity:    models.SeverityCritical,
				Priority:    1,
				FindingRefs: []string{"f1", "f2"},
			},
			{
				ID:          "rem-002",
				Title:       "High Fix",
				Severity:    models.SeverityHigh,
				Priority:    2,
				FindingRefs: []string{"f3"},
			},
			{
				ID:          "rem-003",
				Title:       "Medium Fix",
				Severity:    models.SeverityMedium,
				Priority:    3,
				FindingRefs: []string{"f4"},
			},
		},
	}

	err = gen.generateSummaryReadme(manifest, tmpDir)
	require.NoError(t, err)

	readmePath := filepath.Join(tmpDir, "README.md")
	assert.FileExists(t, readmePath)

	// #nosec G304 -- readmePath is constructed safely from test inputs
	content, err := os.ReadFile(readmePath)
	require.NoError(t, err)
	contentStr := string(content)

	// Check content
	assert.Contains(t, contentStr, "Prismatic Security Fix Bundle")
	assert.Contains(t, contentStr, "Total Findings: 10")
	assert.Contains(t, contentStr, "Critical Priority")
	assert.Contains(t, contentStr, "rem-001: Critical Fix")
	assert.Contains(t, contentStr, "High Priority")
	assert.Contains(t, contentStr, "rem-002: High Fix")
	assert.Contains(t, contentStr, "scripts/apply-all-critical.sh")
}

func TestFixBundleGenerator_generateScripts(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "scripts-test-*")
	require.NoError(t, err)
	defer func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			t.Errorf("Failed to remove temp dir: %v", removeErr)
		}
	}()

	gen := &FixBundleGenerator{
		logger: logger.NewMockLogger(),
	}

	manifest := &remediation.Manifest{
		Remediations: []remediation.Remediation{
			{
				ID:       "rem-001",
				Title:    "Critical S3 Fix",
				Priority: 1,
			},
			{
				ID:       "rem-002",
				Title:    "High IAM Fix",
				Priority: 2,
			},
		},
	}

	err = gen.generateScripts(manifest, tmpDir)
	require.NoError(t, err)

	// Check scripts exist and are executable
	applyScript := filepath.Join(tmpDir, "scripts", "apply-all-critical.sh")
	validateScript := filepath.Join(tmpDir, "scripts", "validate-all.sh")

	assert.FileExists(t, applyScript)
	assert.FileExists(t, validateScript)

	// Check permissions
	info, err := os.Stat(applyScript)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())

	info, err = os.Stat(validateScript)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())

	// Check apply script content
	// #nosec G304 -- applyScript is constructed safely from test inputs
	content, err := os.ReadFile(applyScript)
	require.NoError(t, err)
	contentStr := string(content)
	assert.Contains(t, contentStr, "rem-001")
	assert.Contains(t, contentStr, "Critical S3 Fix")
	assert.NotContains(t, contentStr, "rem-002") // Not critical

	// Check validate script content
	// #nosec G304 -- validateScript is constructed safely from test inputs
	content, err = os.ReadFile(validateScript)
	require.NoError(t, err)
	contentStr = string(content)
	assert.Contains(t, contentStr, "rem-001")
	assert.Contains(t, contentStr, "rem-002")
	assert.Contains(t, contentStr, "Validation Summary")
}

func TestFixBundleGenerator_Integration(t *testing.T) {
	// This test verifies the complete bundle structure
	tmpDir, err := os.MkdirTemp("", "integration-test-*")
	require.NoError(t, err)
	defer func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			t.Errorf("Failed to remove temp dir: %v", removeErr)
		}
	}()

	// Create test findings with enrichments
	findings := []models.Finding{
		{
			ID:          "prowler-s3-001",
			Scanner:     "prowler",
			Type:        "s3_bucket_public_read_access",
			Severity:    models.SeverityCritical,
			Title:       "S3 Bucket allows public read access",
			Description: "S3 bucket 'prod-data' allows public read access",
			Resource:    "prod-data",
		},
		{
			ID:          "trivy-cve-001",
			Scanner:     "trivy",
			Type:        "CVE-2023-1234",
			Severity:    models.SeverityCritical,
			Title:       "Critical vulnerability in node:14",
			Description: "Node.js 14 has a critical security vulnerability",
			Resource:    "app:latest",
		},
		{
			ID:          "kubescape-sec-001",
			Scanner:     "kubescape",
			Type:        "C-0017",
			Severity:    models.SeverityHigh,
			Title:       "Container running as root",
			Description: "Pod 'frontend' is running with root privileges",
			Resource:    "default/frontend",
		},
	}

	log := logger.NewMockLogger()
	gen := NewFixBundleGenerator(log)

	// Generate the bundle
	err = gen.Generate(findings, tmpDir)
	require.NoError(t, err)

	// Verify complete structure
	expectedStructure := []string{
		"manifest.json",
		"README.md",
		"scripts/apply-all-critical.sh",
		"scripts/validate-all.sh",
		"remediations/",
	}

	for _, path := range expectedStructure {
		fullPath := filepath.Join(tmpDir, path)
		if strings.HasSuffix(path, "/") {
			assert.DirExists(t, fullPath)
		} else {
			assert.FileExists(t, fullPath)
		}
	}

	// Verify at least one remediation directory was created
	remDirs, err := os.ReadDir(filepath.Join(tmpDir, "remediations"))
	require.NoError(t, err)
	assert.Greater(t, len(remDirs), 0)

	// Verify remediation directory structure
	for _, remDir := range remDirs {
		if remDir.IsDir() {
			remPath := filepath.Join(tmpDir, "remediations", remDir.Name())
			assert.FileExists(t, filepath.Join(remPath, "README.md"))
			assert.FileExists(t, filepath.Join(remPath, "validation.sh"))
			assert.FileExists(t, filepath.Join(remPath, "llm-prompt.txt"))
		}
	}
}
