package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateFindingID(t *testing.T) {
	tests := []struct {
		name     string
		scanner  string
		findType string
		resource string
		location string
		want     string
	}{
		{
			name:     "basic finding",
			scanner:  "prowler",
			findType: "iam_root_no_mfa",
			resource: "arn:aws:iam::123456789012:root",
			location: "",
			want:     "6e8b8d5f9c4a2f1e",
		},
		{
			name:     "finding with location",
			scanner:  "trivy",
			findType: "CVE-2021-12345",
			resource: "myapp:latest",
			location: "libssl1.1",
			want:     "a3f4e2d1c9b8a7f6",
		},
		{
			name:     "same inputs produce same hash",
			scanner:  "prowler",
			findType: "iam_root_no_mfa",
			resource: "arn:aws:iam::123456789012:root",
			location: "",
			want:     "6e8b8d5f9c4a2f1e",
		},
		{
			name:     "different inputs produce different hash",
			scanner:  "prowler",
			findType: "iam_root_no_mfa",
			resource: "arn:aws:iam::987654321098:root",
			location: "",
			want:     "f1e2d3c4b5a6f7e8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateFindingID(tt.scanner, tt.findType, tt.resource, tt.location)
			assert.Len(t, got, 16, "ID should be 16 characters")

			// Verify deterministic behavior
			got2 := GenerateFindingID(tt.scanner, tt.findType, tt.resource, tt.location)
			assert.Equal(t, got, got2, "Same inputs should produce same ID")

			// Verify different inputs produce different IDs
			if tt.name == "different inputs produce different hash" {
				original := GenerateFindingID("prowler", "iam_root_no_mfa", "arn:aws:iam::123456789012:root", "")
				assert.NotEqual(t, got, original, "Different resources should produce different IDs")
			}
		})
	}
}

func TestNewFinding(t *testing.T) {
	f := NewFinding("trivy", "CVE-2021-12345", "myapp:latest", "libssl1.1")

	assert.NotEmpty(t, f.ID)
	assert.Equal(t, "trivy", f.Scanner)
	assert.Equal(t, "CVE-2021-12345", f.Type)
	assert.Equal(t, "myapp:latest", f.Resource)
	assert.Equal(t, "libssl1.1", f.Location)
	assert.NotNil(t, f.Metadata)
}

func TestFindingIsValid(t *testing.T) {
	tests := []struct {
		name    string
		finding *Finding
		wantErr string
	}{
		{
			name: "valid finding",
			finding: &Finding{
				Scanner:  "prowler",
				Type:     "iam_root_no_mfa",
				Severity: "high",
				Title:    "Root account without MFA",
				Resource: "arn:aws:iam::123456789012:root",
			},
			wantErr: "",
		},
		{
			name: "missing scanner",
			finding: &Finding{
				Type:     "iam_root_no_mfa",
				Severity: "high",
				Title:    "Root account without MFA",
				Resource: "arn:aws:iam::123456789012:root",
			},
			wantErr: "finding missing required field: scanner",
		},
		{
			name: "missing type",
			finding: &Finding{
				Scanner:  "prowler",
				Severity: "high",
				Title:    "Root account without MFA",
				Resource: "arn:aws:iam::123456789012:root",
			},
			wantErr: "finding missing required field: type",
		},
		{
			name: "missing severity",
			finding: &Finding{
				Scanner:  "prowler",
				Type:     "iam_root_no_mfa",
				Title:    "Root account without MFA",
				Resource: "arn:aws:iam::123456789012:root",
			},
			wantErr: "finding missing required field: severity",
		},
		{
			name: "missing title",
			finding: &Finding{
				Scanner:  "prowler",
				Type:     "iam_root_no_mfa",
				Severity: "high",
				Resource: "arn:aws:iam::123456789012:root",
			},
			wantErr: "finding missing required field: title",
		},
		{
			name: "missing resource",
			finding: &Finding{
				Scanner:  "prowler",
				Type:     "iam_root_no_mfa",
				Severity: "high",
				Title:    "Root account without MFA",
			},
			wantErr: "finding missing required field: resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.finding.IsValid()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Critical variations
		{"critical", "critical"},
		{"very-high", "critical"},
		{"very high", "critical"},
		{"veryhigh", "critical"},

		// Standard severities
		{"high", "high"},
		{"medium", "medium"},
		{"moderate", "medium"},
		{"low", "low"},

		// Info variations
		{"info", "info"},
		{"informational", "info"},
		{"negligible", "info"},

		// Unknown
		{"unknown", "unknown"},
		{"random", "unknown"},
		{"", "unknown"},
		// Test case insensitivity
		{"CRITICAL", "critical"},
		{"HIGH", "high"},
		{"MEDIUM", "medium"},
		{"LOW", "low"},
		{"INFO", "info"},
		{"UNKNOWN", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeSeverity(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}
