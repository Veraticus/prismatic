package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		errMsg  string
		wantErr bool
	}{
		{
			name: "valid complete config",
			yaml: `client:
  name: "ACME Corporation"
  environment: "Production"

aws:
  regions:
    - us-east-1
    - us-west-2
  profiles:
    - production

docker:
  registries:
    - registry.acme.com
  containers:
    - api:latest
    - web:latest

kubernetes:
  contexts:
    - prod-cluster
  namespaces:
    - default

endpoints:
  - https://api.acme.com
  - https://www.acme.com

suppressions:
  global:
    date_before: "2023-01-01"
  trivy:
    - CVE-2021-3711
    - CVE-2021-23840
  prowler:
    - iam_user_hardware_mfa_enabled

severity_overrides:
  CVE-2021-3711: low
  check_s3_encryption: medium

metadata_enrichment:
  resources:
    "arn:aws:s3:::acme-public-website":
      owner: "Marketing Team"
      data_classification: "public"
`,
			wantErr: false,
		},
		{
			name: "minimal valid config",
			yaml: `client:
  name: "Test Client"
  environment: "Dev"

aws:
  profiles:
    - default
`,
			wantErr: false,
		},
		{
			name: "missing client name",
			yaml: `client:
  environment: "Production"

aws:
  profiles:
    - default
`,
			wantErr: true,
			errMsg:  "client.name is required",
		},
		{
			name: "missing client environment",
			yaml: `client:
  name: "Test Client"

aws:
  profiles:
    - default
`,
			wantErr: true,
			errMsg:  "client.environment is required",
		},
		{
			name: "no scanning targets",
			yaml: `client:
  name: "Test Client"
  environment: "Dev"
`,
			wantErr: true,
			errMsg:  "at least one scanning target must be configured",
		},
		{
			name: "invalid date format",
			yaml: `client:
  name: "Test Client"
  environment: "Dev"

aws:
  profiles:
    - default

suppressions:
  global:
    date_before: "01/01/2023"
`,
			wantErr: true,
			errMsg:  "invalid date format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")
			err := os.WriteFile(configFile, []byte(tt.yaml), 0644)
			require.NoError(t, err)

			// Load config
			config, err := LoadConfig(configFile)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, config)
			}
		})
	}
}

func TestConfigIsSuppressed(t *testing.T) {
	config := &Config{
		Suppressions: SuppressionConfig{
			Global: GlobalSuppressions{
				DateBefore: "2023-01-01",
			},
			Scanners: map[string][]string{
				"trivy":   {"CVE-2021-3711", "CVE-2021-23840"},
				"prowler": {"iam_user_hardware_mfa_enabled"},
			},
		},
	}

	tests := []struct {
		findingDate time.Time
		name        string
		scanner     string
		findingType string
		wantReason  string
		want        bool
	}{
		{
			name:        "suppressed by date",
			scanner:     "trivy",
			findingType: "CVE-2020-12345",
			findingDate: time.Date(2022, 6, 15, 0, 0, 0, 0, time.UTC),
			want:        true,
			wantReason:  "Finding predates cutoff date 2023-01-01",
		},
		{
			name:        "not suppressed by date",
			scanner:     "trivy",
			findingType: "CVE-2023-12345",
			findingDate: time.Date(2023, 6, 15, 0, 0, 0, 0, time.UTC),
			want:        false,
			wantReason:  "",
		},
		{
			name:        "suppressed by scanner rule",
			scanner:     "trivy",
			findingType: "CVE-2021-3711",
			findingDate: time.Date(2023, 6, 15, 0, 0, 0, 0, time.UTC),
			want:        true,
			wantReason:  "Finding type CVE-2021-3711 is suppressed for trivy scanner",
		},
		{
			name:        "not suppressed",
			scanner:     "nuclei",
			findingType: "exposed-panel",
			findingDate: time.Date(2023, 6, 15, 0, 0, 0, 0, time.UTC),
			want:        false,
			wantReason:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := config.IsSuppressed(tt.scanner, tt.findingType, tt.findingDate)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantReason, reason)
		})
	}
}

func TestConfigGetSeverityOverride(t *testing.T) {
	config := &Config{
		SeverityOverrides: map[string]string{
			"CVE-2021-3711":       "low",
			"check_s3_encryption": "medium",
		},
	}

	tests := []struct {
		name        string
		findingType string
		wantSev     string
		wantFound   bool
	}{
		{
			name:        "override exists",
			findingType: "CVE-2021-3711",
			wantSev:     "low",
			wantFound:   true,
		},
		{
			name:        "override not found",
			findingType: "CVE-2022-12345",
			wantSev:     "",
			wantFound:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sev, found := config.GetSeverityOverride(tt.findingType)
			assert.Equal(t, tt.wantSev, sev)
			assert.Equal(t, tt.wantFound, found)
		})
	}
}

func TestConfigGetResourceMetadata(t *testing.T) {
	config := &Config{
		MetadataEnrichment: MetadataEnrichment{
			Resources: map[string]ResourceMetadata{
				"arn:aws:s3:::acme-public-website": {
					Owner:              "Marketing Team",
					DataClassification: "public",
				},
			},
		},
	}

	tests := []struct {
		name      string
		resource  string
		wantOwner string
		wantFound bool
	}{
		{
			name:      "metadata exists",
			resource:  "arn:aws:s3:::acme-public-website",
			wantFound: true,
			wantOwner: "Marketing Team",
		},
		{
			name:      "metadata not found",
			resource:  "arn:aws:s3:::other-bucket",
			wantFound: false,
			wantOwner: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata, found := config.GetResourceMetadata(tt.resource)
			assert.Equal(t, tt.wantFound, found)
			if found {
				assert.Equal(t, tt.wantOwner, metadata.Owner)
			}
		})
	}
}
