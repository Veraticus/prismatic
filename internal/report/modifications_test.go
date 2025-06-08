package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadModifications(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		errMsg  string
		wantErr bool
	}{
		{
			name: "valid modifications file",
			yaml: `version: "1.0"
last_modified: 2024-01-15T10:00:00Z
author: "security-team@example.com"
description: "Q1 2024 modifications"
suppressions:
  - finding_id: "finding-123"
    reason: "False positive - intentional configuration"
    suppressed_by: "john.doe@example.com"
    suppressed_at: 2024-01-15T10:00:00Z
overrides:
  - finding_id: "finding-456"
    new_severity: "low"
    reason: "Mitigating controls in place"
    overridden_by: "jane.smith@example.com"
    overridden_at: 2024-01-15T10:00:00Z
comments:
  finding-789: "Tracking in JIRA SEC-123"
`,
			wantErr: false,
		},
		{
			name: "invalid version",
			yaml: `version: "2.0"
suppressions: []
overrides: []
`,
			wantErr: true,
			errMsg:  "unsupported modifications version: 2.0",
		},
		{
			name: "invalid severity",
			yaml: `version: "1.0"
suppressions: []
overrides:
  - finding_id: "finding-123"
    new_severity: "extreme"
    reason: "Test"
    overridden_by: "test@example.com"
    overridden_at: 2024-01-15T10:00:00Z
`,
			wantErr: true,
			errMsg:  "invalid severity 'extreme'",
		},
		{
			name: "malformed yaml",
			yaml: `version: "1.0"
suppressions:
  - finding_id: [invalid
`,
			wantErr: true,
			errMsg:  "parsing modifications YAML",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			modsFile := filepath.Join(tmpDir, "modifications.yaml")
			err := os.WriteFile(modsFile, []byte(tt.yaml), 0600)
			require.NoError(t, err)

			// Load modifications
			mods, err := LoadModifications(modsFile)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, mods)
				assert.Equal(t, "1.0", mods.Version)
			}
		})
	}
}

func TestApplyModifications(t *testing.T) {
	// Create test findings
	findings := []models.Finding{
		{
			ID:       "finding-123",
			Title:    "Test Finding 1",
			Severity: "high",
			Scanner:  "test-scanner",
		},
		{
			ID:       "finding-456",
			Title:    "Test Finding 2",
			Severity: "critical",
			Scanner:  "test-scanner",
		},
		{
			ID:       "finding-789",
			Title:    "Test Finding 3",
			Severity: "medium",
			Scanner:  "test-scanner",
		},
	}

	// Create modifications
	now := time.Now()
	futureExpiry := now.Add(24 * time.Hour)
	pastExpiry := now.Add(-24 * time.Hour)

	mods := &Modifications{
		Version:      "1.0",
		LastModified: now,
		Author:       "test@example.com",
		Suppressions: []Suppression{
			{
				FindingID:    "finding-123",
				Reason:       "Test suppression",
				SuppressedBy: "test@example.com",
				SuppressedAt: now,
				ExpiresAt:    &futureExpiry,
			},
			{
				FindingID:    "finding-999", // Non-existent finding
				Reason:       "Should not affect anything",
				SuppressedBy: "test@example.com",
				SuppressedAt: now,
			},
			{
				FindingID:    "finding-789",
				Reason:       "Expired suppression",
				SuppressedBy: "test@example.com",
				SuppressedAt: now.Add(-48 * time.Hour),
				ExpiresAt:    &pastExpiry,
			},
		},
		Overrides: []SeverityOverride{
			{
				FindingID:    "finding-456",
				NewSeverity:  "low",
				Reason:       "Test override",
				OverriddenBy: "test@example.com",
				OverriddenAt: now,
			},
		},
		Comments: map[string]string{
			"finding-789": "Test comment",
		},
	}

	// Apply modifications
	modified := mods.ApplyModifications(findings)

	// Verify results
	assert.Len(t, modified, 3)

	// Check finding-123 (should be suppressed)
	assert.True(t, modified[0].Suppressed)
	assert.Equal(t, "Test suppression", modified[0].SuppressionReason)

	// Check finding-456 (should have severity overridden)
	assert.Equal(t, "low", modified[1].Severity)
	assert.Equal(t, "critical", modified[1].OriginalSeverity)
	assert.False(t, modified[1].Suppressed)

	// Check finding-789 (should not be suppressed due to expiry, but should have comment)
	assert.False(t, modified[2].Suppressed)
	assert.Equal(t, "Test comment", modified[2].Comment)
}

func TestSaveModifications(t *testing.T) {
	mods := Example()

	// Save to temp file
	tmpDir := t.TempDir()
	modsFile := filepath.Join(tmpDir, "test-mods.yaml")

	err := SaveModifications(modsFile, mods)
	require.NoError(t, err)

	// Verify file exists
	info, err := os.Stat(modsFile)
	assert.NoError(t, err)
	assert.True(t, info.Size() > 0)

	// Load it back
	loaded, err := LoadModifications(modsFile)
	require.NoError(t, err)
	assert.Equal(t, "1.0", loaded.Version)
	assert.Len(t, loaded.Suppressions, 2)
	assert.Len(t, loaded.Overrides, 1)
	assert.Len(t, loaded.Comments, 2)
}

func TestIsValidSeverity(t *testing.T) {
	tests := []struct {
		severity string
		valid    bool
	}{
		{"critical", true},
		{"high", true},
		{"medium", true},
		{"low", true},
		{"info", true},
		{"extreme", false},
		{"", false},
		{"HIGH", false}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			assert.Equal(t, tt.valid, isValidSeverity(tt.severity))
		})
	}
}

func TestApplyModificationsIntegration(t *testing.T) {
	// Create a test HTML generator with findings
	findings := []models.Finding{
		{
			ID:          "test-finding-1",
			Title:       "Security Group allows SSH from anywhere",
			Severity:    "high",
			Scanner:     "prowler",
			Resource:    "sg-123456",
			Description: "Security group allows inbound SSH from 0.0.0.0/0",
		},
		{
			ID:          "test-finding-2",
			Title:       "S3 bucket has public read access",
			Severity:    "critical",
			Scanner:     "prowler",
			Resource:    "my-public-bucket",
			Description: "S3 bucket allows public read access",
		},
	}

	// Create modifications file
	modsYAML := `version: "1.0"
last_modified: 2024-01-15T10:00:00Z
author: "security-team@example.com"
description: "Test modifications"
suppressions:
  - finding_id: "test-finding-1"
    reason: "Bastion host - SSH access required"
    suppressed_by: "ops@example.com"
    suppressed_at: 2024-01-15T10:00:00Z
overrides:
  - finding_id: "test-finding-2"
    new_severity: "medium"
    reason: "Bucket contains only public marketing materials"
    overridden_by: "security@example.com"
    overridden_at: 2024-01-15T10:00:00Z
comments:
  test-finding-2: "Verified with marketing team - intentional configuration"
`

	tmpDir := t.TempDir()
	modsFile := filepath.Join(tmpDir, "mods.yaml")
	err := os.WriteFile(modsFile, []byte(modsYAML), 0600)
	require.NoError(t, err)

	// Load and apply modifications
	mods, err := LoadModifications(modsFile)
	require.NoError(t, err)

	modified := mods.ApplyModifications(findings)

	// Verify modifications were applied correctly
	assert.Len(t, modified, 2)

	// First finding should be suppressed
	assert.True(t, modified[0].Suppressed)
	assert.Equal(t, "Bastion host - SSH access required", modified[0].SuppressionReason)

	// Second finding should have severity override and comment
	assert.Equal(t, "medium", modified[1].Severity)
	assert.Equal(t, "critical", modified[1].OriginalSeverity)
	assert.Equal(t, "Verified with marketing team - intentional configuration", modified[1].Comment)
	assert.False(t, modified[1].Suppressed)
}
