package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaseScanner(t *testing.T) {
	config := Config{
		WorkingDir: "/tmp/test",
		Timeout:    300,
		Debug:      true,
		Env: map[string]string{
			"TEST_VAR": "test_value",
		},
	}

	scanner := NewBaseScanner("test-scanner", config)

	// Test Name
	assert.Equal(t, "test-scanner", scanner.Name())

	// Test Config
	assert.Equal(t, config, scanner.Config())

	// Test Version
	assert.Empty(t, scanner.GetVersion())
	scanner.SetVersion("v1.2.3")
	assert.Equal(t, "v1.2.3", scanner.GetVersion())
}

func TestValidateFinding(t *testing.T) {
	tests := []struct {
		finding     *models.Finding
		name        string
		errorMsg    string
		shouldError bool
	}{
		{
			name: "valid finding",
			finding: &models.Finding{
				Scanner:  "test-scanner",
				Type:     "vulnerability",
				Severity: "high",
				Title:    "Test Finding",
				Resource: "test-resource",
			},
			shouldError: false,
		},
		{
			name: "missing scanner",
			finding: &models.Finding{
				Type:     "vulnerability",
				Severity: "high",
				Title:    "Test Finding",
				Resource: "test-resource",
			},
			shouldError: true,
			errorMsg:    "scanner",
		},
		{
			name: "missing type",
			finding: &models.Finding{
				Scanner:  "test-scanner",
				Severity: "high",
				Title:    "Test Finding",
				Resource: "test-resource",
			},
			shouldError: true,
			errorMsg:    "type",
		},
		{
			name: "missing severity",
			finding: &models.Finding{
				Scanner:  "test-scanner",
				Type:     "vulnerability",
				Title:    "Test Finding",
				Resource: "test-resource",
			},
			shouldError: true,
			errorMsg:    "severity",
		},
		{
			name: "missing title",
			finding: &models.Finding{
				Scanner:  "test-scanner",
				Type:     "vulnerability",
				Severity: "high",
				Resource: "test-resource",
			},
			shouldError: true,
			errorMsg:    "title",
		},
		{
			name: "missing resource",
			finding: &models.Finding{
				Scanner:  "test-scanner",
				Type:     "vulnerability",
				Severity: "high",
				Title:    "Test Finding",
			},
			shouldError: true,
			errorMsg:    "resource",
		},
		{
			name: "severity normalization",
			finding: &models.Finding{
				Scanner:  "test-scanner",
				Type:     "vulnerability",
				Severity: "very-high",
				Title:    "Test Finding",
				Resource: "test-resource",
			},
			shouldError: false,
		},
		{
			name: "auto-generate ID",
			finding: &models.Finding{
				ID:       "",
				Scanner:  "test-scanner",
				Type:     "vulnerability",
				Severity: "high",
				Title:    "Test Finding",
				Resource: "test-resource",
				Location: "line 42",
			},
			shouldError: false,
		},
		{
			name: "preserve existing ID",
			finding: &models.Finding{
				ID:       "existing-id",
				Scanner:  "test-scanner",
				Type:     "vulnerability",
				Severity: "high",
				Title:    "Test Finding",
				Resource: "test-resource",
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFinding(tt.finding)
			if tt.shouldError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)

				// Check severity normalization
				if tt.name == "severity normalization" {
					assert.Equal(t, "critical", tt.finding.Severity)
				}

				// Check ID generation
				if tt.name == "auto-generate ID" {
					assert.NotEmpty(t, tt.finding.ID)
				}

				// Check ID preservation
				if tt.name == "preserve existing ID" {
					assert.Equal(t, "existing-id", tt.finding.ID)
				}
			}
		})
	}
}

// TestError removed as structured error system is deprecated

// Mock scanner for testing interface implementation.
type mockTestScanner struct {
	scanFunc  func(ctx context.Context) (*models.ScanResult, error)
	parseFunc func(raw []byte) ([]models.Finding, error)
	BaseScanner
}

func (m *mockTestScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
	if m.scanFunc != nil {
		return m.scanFunc(ctx)
	}
	return &models.ScanResult{
		Scanner:   m.Name(),
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Findings:  []models.Finding{},
	}, nil
}

func (m *mockTestScanner) ParseResults(raw []byte) ([]models.Finding, error) {
	if m.parseFunc != nil {
		return m.parseFunc(raw)
	}
	return []models.Finding{}, nil
}

func TestScannerInterface(t *testing.T) {
	// Ensure mockTestScanner implements Scanner interface
	var _ Scanner = &mockTestScanner{}

	// Test with custom behavior
	mock := &mockTestScanner{
		BaseScanner: *NewBaseScanner("test", Config{}),
		scanFunc: func(_ context.Context) (*models.ScanResult, error) {
			return &models.ScanResult{
				Scanner: "test",
				Findings: []models.Finding{
					{
						ID:       "test-finding",
						Scanner:  "test",
						Type:     "test-type",
						Severity: "high",
						Title:    "Test",
						Resource: "test-resource",
					},
				},
			}, nil
		},
		parseFunc: func(_ []byte) ([]models.Finding, error) {
			return []models.Finding{
				{
					ID: "parsed-finding",
				},
			}, nil
		},
	}

	// Test Scan
	ctx := context.Background()
	result, err := mock.Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, "test", result.Scanner)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "test-finding", result.Findings[0].ID)

	// Test ParseResults
	findings, err := mock.ParseResults([]byte("test"))
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "parsed-finding", findings[0].ID)
}

func TestConfig(t *testing.T) {
	config := Config{
		WorkingDir: "/test/dir",
		Timeout:    600,
		Debug:      true,
		Env: map[string]string{
			"AWS_PROFILE": "test",
			"AWS_REGION":  "us-east-1",
		},
	}

	// Test all fields are set correctly
	assert.Equal(t, "/test/dir", config.WorkingDir)
	assert.Equal(t, 600, config.Timeout)
	assert.True(t, config.Debug)
	assert.Equal(t, "test", config.Env["AWS_PROFILE"])
	assert.Equal(t, "us-east-1", config.Env["AWS_REGION"])
}
