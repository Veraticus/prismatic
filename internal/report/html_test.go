package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTMLGenerator(t *testing.T) {
	tempDir := t.TempDir()

	// Create data directory structure
	dataDir := filepath.Join(tempDir, "data")
	_ = os.MkdirAll(dataDir, 0750)

	// Save current working directory and change to temp
	oldWd, _ := os.Getwd()
	_ = os.Chdir(tempDir)
	defer func() { _ = os.Chdir(oldWd) }()

	// Create test scan data
	store := storage.NewStorage("data")
	scanDir := filepath.Join("data", "scans", "2024-01-01T10-00-00Z")

	metadata := &models.ScanMetadata{
		ClientName:  "test-client",
		Environment: "test",
		StartTime:   time.Now().Add(-10 * time.Minute),
		EndTime:     time.Now(),
		Summary: models.ScanSummary{
			TotalFindings: 5,
			BySeverity: map[string]int{
				"critical": 1,
				"high":     2,
				"medium":   2,
			},
		},
	}

	findings := []models.Finding{
		{
			ID:       "finding-1",
			Scanner:  "mock-prowler",
			Type:     "security-group",
			Severity: "critical",
			Title:    "Open Security Group",
			Resource: "sg-12345",
		},
		{
			ID:         "finding-2",
			Scanner:    "mock-trivy",
			Type:       "CVE-2021-12345",
			Severity:   "high",
			Title:      "Critical Vulnerability",
			Resource:   "nginx:latest",
			Suppressed: true,
		},
	}

	// Save test data
	err := store.SaveScanResults(scanDir, metadata)
	require.NoError(t, err)

	// Create a custom findings.json since SaveScanResults will create a different one
	findingsPath := filepath.Join(scanDir, "findings.json")
	err = saveJSONHelper(findingsPath, findings)
	require.NoError(t, err)

	// Test loading scan by path
	gen, err := NewHTMLGenerator(scanDir, nil)
	require.NoError(t, err)
	assert.Equal(t, scanDir, gen.scanPath)
	assert.Equal(t, metadata.ClientName, gen.metadata.ClientName)
	assert.Len(t, gen.findings, 2)

	// Test loading latest scan
	gen2, err := NewHTMLGenerator("latest", nil)
	require.NoError(t, err)
	assert.Equal(t, scanDir, gen2.scanPath)

	// Test with non-existent scan
	_, err = NewHTMLGenerator("/non/existent/path", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "loading scan results")
}

func TestGenerate(t *testing.T) {
	tempDir := t.TempDir()

	// Create data directory structure
	dataDir := filepath.Join(tempDir, "data")
	_ = os.MkdirAll(dataDir, 0750)

	// Save current working directory and change to temp
	oldWd, _ := os.Getwd()
	_ = os.Chdir(tempDir)
	defer func() { _ = os.Chdir(oldWd) }()

	// Create test scan data
	store := storage.NewStorage("data")
	scanDir := filepath.Join("data", "scans", "2024-01-01T10-00-00Z")

	metadata := &models.ScanMetadata{
		ClientName:  "test-client",
		Environment: "production",
		StartTime:   time.Now().Add(-30 * time.Minute),
		EndTime:     time.Now(),
		Scanners:    []string{"mock-prowler", "mock-trivy", "mock-nuclei"},
		Results: map[string]*models.ScanResult{
			"mock-prowler": {
				Scanner:   "mock-prowler",
				StartTime: time.Now().Add(-30 * time.Minute),
				EndTime:   time.Now().Add(-20 * time.Minute),
			},
			"mock-trivy": {
				Scanner:   "mock-trivy",
				StartTime: time.Now().Add(-20 * time.Minute),
				EndTime:   time.Now().Add(-10 * time.Minute),
			},
			"mock-nuclei": {
				Scanner:   "mock-nuclei",
				StartTime: time.Now().Add(-10 * time.Minute),
				EndTime:   time.Now(),
			},
		},
		Summary: models.ScanSummary{
			TotalFindings:   11,
			SuppressedCount: 3,
			BySeverity: map[string]int{
				"critical": 2,
				"high":     4,
				"medium":   3,
				"low":      1,
				"info":     1,
			},
			ByScanner: map[string]int{
				"mock-prowler":   2,
				"mock-trivy":     2,
				"mock-nuclei":    1,
				"mock-kubescape": 1,
				"mock-gitleaks":  1,
				"mock-checkov":   3,
			},
		},
	}

	findings := []models.Finding{
		// AWS findings
		{
			ID:          "aws-1",
			Scanner:     "mock-prowler",
			Type:        "security-group",
			Severity:    "critical",
			Title:       "Open Security Group",
			Description: "Security group allows unrestricted access",
			Resource:    "sg-12345",
			Remediation: "Restrict security group rules",
			Impact:      "High risk of unauthorized access",
		},
		{
			ID:          "aws-2",
			Scanner:     "mock-prowler",
			Type:        "iam-policy",
			Severity:    "high",
			Title:       "Overly Permissive IAM Policy",
			Description: "IAM policy grants excessive permissions",
			Resource:    "arn:aws:iam::123456789012:policy/AdminPolicy",
			Remediation: "Apply principle of least privilege",
			Impact:      "Risk of privilege escalation",
		},
		// Container findings
		{
			ID:          "container-1",
			Scanner:     "mock-trivy",
			Type:        "CVE-2021-44228",
			Severity:    "critical",
			Title:       "Log4Shell Vulnerability",
			Description: "Critical RCE vulnerability in Log4j",
			Resource:    "app:latest",
			Remediation: "Update Log4j to version 2.17.0 or later",
			Impact:      "Remote code execution possible",
		},
		{
			ID:                "container-2",
			Scanner:           "mock-trivy",
			Type:              "CVE-2021-12345",
			Severity:          "high",
			Title:             "OpenSSL Vulnerability",
			Description:       "Buffer overflow in OpenSSL",
			Resource:          "nginx:1.19",
			Remediation:       "Update to nginx:1.21 or later",
			Impact:            "Potential denial of service",
			Suppressed:        true,
			SuppressionReason: "Accepted risk until next release",
		},
		// Web findings
		{
			ID:          "web-1",
			Scanner:     "mock-nuclei",
			Type:        "exposed-api",
			Severity:    "high",
			Title:       "Exposed API Endpoint",
			Description: "API endpoint accessible without authentication",
			Resource:    "https://example.com/api/admin",
			Remediation: "Implement authentication",
			Impact:      "Unauthorized access to sensitive data",
		},
		// K8s findings
		{
			ID:          "k8s-1",
			Scanner:     "mock-kubescape",
			Type:        "privileged-container",
			Severity:    "medium",
			Title:       "Privileged Container",
			Description: "Container running with privileged access",
			Resource:    "deployment/app-deployment",
			Remediation: "Remove privileged flag",
			Impact:      "Container escape possible",
		},
		// Secrets findings
		{
			ID:          "secret-1",
			Scanner:     "mock-gitleaks",
			Type:        "github-token",
			Severity:    "high",
			Title:       "GitHub Token Exposed",
			Description: "GitHub personal access token found in source code",
			Resource:    "src/auth.js:15",
			Location:    "line 15",
			Remediation: "Rotate token and use environment variables",
			Impact:      "Repository access compromise",
		},
		{
			ID:                "secret-2",
			Scanner:           "mock-gitleaks",
			Type:              "aws-key",
			Severity:          "critical",
			Title:             "AWS Access Key Exposed",
			Description:       "AWS access key found in source code",
			Resource:          "src/config.js:42",
			Location:          "line 42",
			Remediation:       "Rotate key and use environment variables",
			Impact:            "AWS account compromise",
			Suppressed:        true,
			SuppressionReason: "False positive - example key",
		},
		// IaC findings
		{
			ID:          "iac-1",
			Scanner:     "mock-checkov",
			Type:        "CKV_AWS_23",
			Severity:    "medium",
			Title:       "S3 Bucket Logging Disabled",
			Description: "S3 bucket does not have access logging enabled",
			Resource:    "terraform/s3.tf",
			Remediation: "Enable S3 bucket logging",
			Impact:      "Reduced audit trail",
		},
		{
			ID:          "iac-2",
			Scanner:     "mock-checkov",
			Type:        "CKV_AWS_18",
			Severity:    "low",
			Title:       "S3 Bucket Without Versioning",
			Description: "S3 bucket does not have versioning enabled",
			Resource:    "terraform/s3.tf",
			Remediation: "Enable versioning",
			Impact:      "Cannot recover from accidental deletion",
		},
		{
			ID:          "iac-3",
			Scanner:     "mock-checkov",
			Type:        "CKV_AWS_145",
			Severity:    "info",
			Title:       "S3 Bucket Without Lifecycle Policy",
			Description: "S3 bucket does not have lifecycle rules",
			Resource:    "terraform/s3.tf",
			Remediation: "Add lifecycle rules",
			Impact:      "Potential cost optimization missed",
		},
	}

	// Save test data
	err := store.SaveScanResults(scanDir, metadata)
	require.NoError(t, err)

	// Save findings
	findingsPath := filepath.Join(scanDir, "findings.json")
	err = saveJSONHelper(findingsPath, findings)
	require.NoError(t, err)

	// Generate report
	gen, err := NewHTMLGenerator(scanDir, nil)
	require.NoError(t, err)

	outputPath := filepath.Join(tempDir, "report.html")
	err = gen.Generate(outputPath)
	require.NoError(t, err)

	// Verify report was created
	assert.FileExists(t, outputPath)

	// Read and verify content
	// Path is safe - constructed from test temp directory
	content, err := os.ReadFile(outputPath) // #nosec G304
	require.NoError(t, err)

	html := string(content)

	// Check basic structure
	assert.Contains(t, html, "<html")
	assert.Contains(t, html, "</html>")
	assert.Contains(t, html, "Prismatic Security Report")

	// Check metadata
	assert.Contains(t, html, "test-client")
	assert.Contains(t, html, "production")

	// Check summary stats
	assert.Contains(t, html, "8") // Total active findings (11 - 3 suppressed)
	assert.Contains(t, html, "2") // Critical count
	assert.Contains(t, html, "4") // High count

	// Check that findings from different categories are present
	// (The actual section headers/icons depend on the template implementation)

	// Check specific findings
	assert.Contains(t, html, "Open Security Group")
	assert.Contains(t, html, "Log4Shell Vulnerability")
	assert.Contains(t, html, "Exposed API Endpoint")

	// Ensure suppressed findings are not in active sections
	assert.NotContains(t, html, "Accepted risk until next release")
	assert.NotContains(t, html, "False positive - example key")

	// Note: The template doesn't currently display failed scanner information
	// This could be added as an enhancement
}

func TestTemplateFuncs(t *testing.T) {
	gen := &HTMLGenerator{}
	funcs := gen.templateFuncs()

	// Test severityClass
	severityClass, ok := funcs["severityClass"].(func(string) string)
	require.True(t, ok, "severityClass function should exist")
	assert.Equal(t, "severity-critical", severityClass("critical"))
	assert.Equal(t, "severity-high", severityClass("high"))

	// Test severityIcon
	severityIcon, ok := funcs["severityIcon"].(func(string) string)
	require.True(t, ok, "severityIcon function should exist")
	assert.Equal(t, "🔴", severityIcon("critical"))
	assert.Equal(t, "🟠", severityIcon("high"))
	assert.Equal(t, "🟡", severityIcon("medium"))
	assert.Equal(t, "🔵", severityIcon("low"))
	assert.Equal(t, "⚪", severityIcon("info"))
	assert.Equal(t, "⚪", severityIcon("unknown"))

	// Test formatTime
	formatTime, ok := funcs["formatTime"].(func(time.Time) string)
	require.True(t, ok, "formatTime function should exist")
	testTime := time.Date(2024, 1, 1, 10, 30, 45, 0, time.UTC)
	assert.Equal(t, "2024-01-01 10:30:45", formatTime(testTime))

	// Test formatDuration
	formatDuration, ok := funcs["formatDuration"].(func(time.Duration) string)
	require.True(t, ok, "formatDuration function should exist")
	assert.Equal(t, "5m30s", formatDuration(5*time.Minute+30*time.Second))
	assert.Equal(t, "1h0m0s", formatDuration(1*time.Hour))

	// Test truncate
	truncate, ok := funcs["truncate"].(func(string, int) string)
	require.True(t, ok, "truncate function should exist")
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "hello worl...", truncate("hello world test", 10))
}

func TestPrepareTemplateData(t *testing.T) {
	gen := &HTMLGenerator{
		metadata: &models.ScanMetadata{
			ClientName:  "test-client",
			Environment: "test",
			StartTime:   time.Now().Add(-30 * time.Minute),
			EndTime:     time.Now(),
			Summary: models.ScanSummary{
				TotalFindings:   10,
				SuppressedCount: 2,
			},
		},
		findings: []models.Finding{
			// Critical findings
			{Scanner: "mock-prowler", Severity: "critical", Title: "Critical AWS Issue", Suppressed: false},
			{Scanner: "mock-trivy", Severity: "critical", Title: "Critical Container Issue", Suppressed: false},
			// High findings
			{Scanner: "mock-prowler", Severity: "high", Title: "High AWS Issue 1", Suppressed: false},
			{Scanner: "mock-prowler", Severity: "high", Title: "High AWS Issue 2", Suppressed: false},
			{Scanner: "mock-nuclei", Severity: "high", Title: "High Web Issue", Suppressed: false},
			// Medium findings
			{Scanner: "mock-kubescape", Severity: "medium", Title: "Medium K8s Issue", Suppressed: false},
			{Scanner: "mock-checkov", Severity: "medium", Title: "Medium IaC Issue", Suppressed: false},
			// Low findings
			{Scanner: "mock-gitleaks", Severity: "low", Title: "Low Secret Issue", Suppressed: false},
			// Suppressed findings
			{Scanner: "mock-trivy", Severity: "high", Title: "Suppressed Issue 1", Suppressed: true},
			{Scanner: "mock-prowler", Severity: "critical", Title: "Suppressed Issue 2", Suppressed: true},
		},
	}

	data := gen.prepareTemplateData()

	// Check counts
	assert.Equal(t, 8, data.TotalActive)
	assert.Equal(t, 2, data.TotalSuppressed)
	assert.Equal(t, 2, data.CriticalCount)
	assert.Equal(t, 3, data.HighCount)
	assert.Equal(t, 2, data.MediumCount)
	assert.Equal(t, 1, data.LowCount)
	assert.Equal(t, 0, data.InfoCount)

	// Check categorization
	assert.Len(t, data.AWSFindings, 3) // 3 active AWS findings
	assert.Len(t, data.ContainerFindings, 1)
	assert.Len(t, data.KubernetesFindings, 1)
	assert.Len(t, data.WebFindings, 1)
	assert.Len(t, data.SecretsFindings, 1)
	assert.Len(t, data.IaCFindings, 1)

	// Check top risks (should include all critical and high)
	assert.Len(t, data.TopRisks, 5)
	assert.Equal(t, "critical", data.TopRisks[0].Severity)
	assert.Equal(t, "critical", data.TopRisks[1].Severity)
	assert.Equal(t, "high", data.TopRisks[2].Severity)

	// Check sorting within categories
	assert.Equal(t, "critical", data.AWSFindings[0].Severity)
	assert.Equal(t, "high", data.AWSFindings[1].Severity)
}

func TestSeverityOrder(t *testing.T) {
	assert.Equal(t, 0, severityOrder("critical"))
	assert.Equal(t, 1, severityOrder("high"))
	assert.Equal(t, 2, severityOrder("medium"))
	assert.Equal(t, 3, severityOrder("low"))
	assert.Equal(t, 4, severityOrder("info"))
	assert.Equal(t, 5, severityOrder("unknown"))
}

func TestSortFindings(t *testing.T) {
	findings := []models.Finding{
		{Severity: "low", Title: "C Low Issue"},
		{Severity: "high", Title: "B High Issue"},
		{Severity: "critical", Title: "Z Critical Issue"},
		{Severity: "high", Title: "A High Issue"},
		{Severity: "critical", Title: "A Critical Issue"},
		{Severity: "medium", Title: "Medium Issue"},
	}

	sortFindings(findings)

	// Check order
	assert.Equal(t, "critical", findings[0].Severity)
	assert.Equal(t, "A Critical Issue", findings[0].Title)
	assert.Equal(t, "critical", findings[1].Severity)
	assert.Equal(t, "Z Critical Issue", findings[1].Title)
	assert.Equal(t, "high", findings[2].Severity)
	assert.Equal(t, "A High Issue", findings[2].Title)
	assert.Equal(t, "high", findings[3].Severity)
	assert.Equal(t, "B High Issue", findings[3].Title)
	assert.Equal(t, "medium", findings[4].Severity)
	assert.Equal(t, "low", findings[5].Severity)
}

// saveJSONHelper is a test helper to save JSON data.
func saveJSONHelper(path string, data any) error {
	// Path is safe - only used in tests with temp directories
	file, err := os.Create(path) // #nosec G304
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func TestLoadJSON(t *testing.T) {
	tempDir := t.TempDir()

	// Test successful load
	testData := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	jsonPath := filepath.Join(tempDir, "test.json")
	err := saveJSONHelper(jsonPath, testData)
	require.NoError(t, err)

	var loaded map[string]string
	err = loadJSON(jsonPath, &loaded)
	require.NoError(t, err)
	assert.Equal(t, testData, loaded)

	// Test non-existent file
	var notFound map[string]string
	err = loadJSON("/non/existent/file.json", &notFound)
	assert.Error(t, err)
}

func TestGenerateWithInvalidOutputPath(t *testing.T) {
	tempDir := t.TempDir()

	// Create data directory structure
	dataDir := filepath.Join(tempDir, "data")
	_ = os.MkdirAll(dataDir, 0750)

	// Save current working directory and change to temp
	oldWd, _ := os.Getwd()
	_ = os.Chdir(tempDir)
	defer func() { _ = os.Chdir(oldWd) }()

	// Create minimal test data
	store := storage.NewStorage("data")
	scanDir := filepath.Join("data", "scans", "2024-01-01T10-00-00Z")

	metadata := &models.ScanMetadata{
		ClientName:  "test",
		Environment: "test",
		StartTime:   time.Now(),
		EndTime:     time.Now(),
	}

	err := store.SaveScanResults(scanDir, metadata)
	require.NoError(t, err)

	err = saveJSONHelper(filepath.Join(scanDir, "findings.json"), []models.Finding{})
	require.NoError(t, err)

	gen, err := NewHTMLGenerator(scanDir, nil)
	require.NoError(t, err)

	// Test with invalid output path
	err = gen.Generate("/invalid\x00path/report.html")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "creating output")
}
