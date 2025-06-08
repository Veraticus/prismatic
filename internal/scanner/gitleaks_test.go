package scanner

import (
	"testing"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitleaksScanner_ParseResults(t *testing.T) {
	scanner := NewGitleaksScanner(Config{}, ".")

	tests := []struct {
		validate func(t *testing.T, findings []models.Finding)
		name     string
		input    string
		expected int
	}{
		{
			name:     "empty results",
			input:    "",
			expected: 0,
		},
		{
			name: "single secret finding",
			input: `[{
				"Description": "AWS Access Key",
				"StartLine": 15,
				"EndLine": 15,
				"StartColumn": 20,
				"EndColumn": 60,
				"Match": "AKIAIOSFODNN7EXAMPLE",
				"File": "config.yaml",
				"Commit": "abc123",
				"Author": "John Doe",
				"Email": "john@example.com",
				"Date": "2023-01-01T10:00:00Z",
				"RuleID": "aws-access-token",
				"Fingerprint": "12345"
			}]`,
			expected: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				finding := findings[0]
				assert.Equal(t, "secret", finding.Type)
				assert.Equal(t, "critical", finding.Severity)
				assert.Equal(t, "config.yaml", finding.Resource)
				assert.Equal(t, "config.yaml:15", finding.Location)
				assert.Contains(t, finding.Title, "AWS Access Key")
				assert.Contains(t, finding.Description, "config.yaml")
				assert.Contains(t, finding.Description, "line 15")
				assert.Contains(t, finding.Remediation, "rotate")
				assert.Equal(t, "aws-access-token", finding.Metadata["rule_id"])
				assert.Equal(t, "abc123", finding.Metadata["commit"])
				assert.Equal(t, "John Doe", finding.Metadata["author"])
				assert.Equal(t, "AKIA...MPLE", finding.Metadata["match_pattern"])
			},
		},
		{
			name: "multiple secrets",
			input: `[
				{
					"Description": "GitHub Personal Access Token",
					"StartLine": 10,
					"File": ".env",
					"RuleID": "github-pat",
					"Match": "ghp_abcdefghijklmnopqrstuvwxyz123456"
				},
				{
					"Description": "Generic API Key",
					"StartLine": 25,
					"File": "app.js",
					"RuleID": "generic-api-key",
					"Match": "sk-1234567890abcdef"
				}
			]`,
			expected: 2,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				assert.Len(t, findings, 2)

				// Check first finding
				assert.Equal(t, ".env", findings[0].Resource)
				assert.Contains(t, findings[0].Title, "GitHub Personal Access Token")

				// Check second finding
				assert.Equal(t, "app.js", findings[1].Resource)
				assert.Contains(t, findings[1].Title, "Generic API Key")
			},
		},
		{
			name: "secret without line number",
			input: `[{
				"Description": "Private Key",
				"File": "id_rsa",
				"RuleID": "private-key",
				"Match": "-----BEGIN RSA PRIVATE KEY-----"
			}]`,
			expected: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				finding := findings[0]
				assert.Equal(t, "id_rsa", finding.Resource)
				assert.Equal(t, "id_rsa", finding.Location) // No line number
				assert.NotContains(t, finding.Description, "line")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := scanner.ParseResults([]byte(tt.input))
			require.NoError(t, err)
			assert.Len(t, findings, tt.expected)

			if tt.validate != nil {
				tt.validate(t, findings)
			}
		})
	}
}

func TestGitleaksScanner_ParseResults_InvalidJSON(t *testing.T) {
	scanner := NewGitleaksScanner(Config{}, ".")

	_, err := scanner.ParseResults([]byte("invalid json"))
	assert.Error(t, err)
	assert.IsType(t, &ScannerError{}, err)
}

func TestGitleaksScanner_RedactSecret(t *testing.T) {
	scanner := NewGitleaksScanner(Config{}, ".")

	tests := []struct {
		input    string
		expected string
	}{
		{"short", "***REDACTED***"},
		{"12345678", "***REDACTED***"},
		{"123456789", "1234...6789"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA...MPLE"},
		{"ghp_abcdefghijklmnopqrstuvwxyz123456", "ghp_...3456"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, scanner.redactSecret(tt.input))
		})
	}
}

func TestNewGitleaksScanner(t *testing.T) {
	// Test with empty path defaults to current directory
	scanner1 := NewGitleaksScanner(Config{}, "")
	assert.Equal(t, ".", scanner1.targetPath)

	// Test with specific path
	scanner2 := NewGitleaksScanner(Config{}, "/path/to/repo")
	assert.Equal(t, "/path/to/repo", scanner2.targetPath)
}
