package trivy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/joshsymonds/prismatic/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		config  *Config
		name    string
		errMsg  string
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "invalid severity",
			config: &Config{
				Severities: []string{"CRITICAL", "INVALID"},
			},
			wantErr: true,
			errMsg:  "invalid severity: INVALID",
		},
		{
			name: "invalid vuln type",
			config: &Config{
				VulnTypes: []string{"vuln", "invalid"},
			},
			wantErr: true,
			errMsg:  "invalid vulnerability type: invalid",
		},
		{
			name: "negative timeout",
			config: &Config{
				Timeout: -1 * time.Minute,
			},
			wantErr: true,
			errMsg:  "timeout cannot be negative",
		},
		{
			name: "negative parallel",
			config: &Config{
				Parallel: -1,
			},
			wantErr: true,
			errMsg:  "parallel cannot be negative",
		},
		{
			name: "all valid severities",
			config: &Config{
				Severities: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
			},
			wantErr: false,
		},
		{
			name: "all valid vuln types",
			config: &Config{
				VulnTypes: []string{"vuln", "secret", "misconfig", "license"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFactory_Name(t *testing.T) {
	f := &Factory{}
	assert.Equal(t, "trivy", f.Name())
}

func TestFactory_DefaultConfig(t *testing.T) {
	f := &Factory{}
	config := f.DefaultConfig()

	trivyConfig, ok := config.(*Config)
	require.True(t, ok)

	assert.NotEmpty(t, trivyConfig.CacheDir)
	assert.Equal(t, []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}, trivyConfig.Severities)
	assert.Equal(t, []string{"vuln", "secret", "misconfig"}, trivyConfig.VulnTypes)
	assert.Equal(t, 30*time.Minute, trivyConfig.Timeout)
	assert.Equal(t, 3, trivyConfig.Parallel)
	assert.False(t, trivyConfig.IgnoreUnfixed)
	assert.False(t, trivyConfig.OfflineMode)
	assert.False(t, trivyConfig.SkipDBUpdate)
}

func TestFactory_Capabilities(t *testing.T) {
	f := &Factory{}
	caps := f.Capabilities()

	assert.True(t, caps.SupportsImages)
	assert.True(t, caps.SupportsFilesystems)
	assert.True(t, caps.SupportsRepositories)
	assert.False(t, caps.SupportsCloud)
	assert.True(t, caps.SupportsKubernetes)
	assert.False(t, caps.SupportsWeb)
	assert.True(t, caps.SupportsConcurrency)
	assert.True(t, caps.RequiresNetwork)
	assert.Equal(t, 10, caps.MaxConcurrency)
}

func TestFactory_Create(t *testing.T) {
	f := &Factory{}
	config := DefaultConfig()

	tests := []struct {
		config  scanner.Config
		name    string
		errMsg  string
		targets scanner.Targets
		wantErr bool
	}{
		{
			name:   "valid creation",
			config: config,
			targets: scanner.Targets{
				Images: []scanner.Image{{Name: "nginx:latest"}},
			},
			wantErr: false,
		},
		{
			name:   "wrong config type",
			config: struct{ scanner.Config }{},
			targets: scanner.Targets{
				Images: []scanner.Image{{Name: "nginx:latest"}},
			},
			wantErr: true,
			errMsg:  "invalid config type",
		},
		{
			name:    "no targets",
			config:  config,
			targets: scanner.Targets{},
			wantErr: true,
			errMsg:  "no targets configured",
		},
		{
			name:   "unsupported cloud targets",
			config: config,
			targets: scanner.Targets{
				CloudAccounts: []scanner.CloudAccount{{Provider: "aws"}},
			},
			wantErr: true,
			errMsg:  "cloud accounts not supported",
		},
		{
			name:   "unsupported web targets",
			config: config,
			targets: scanner.Targets{
				WebApplications: []scanner.WebApplication{{URL: "https://example.com"}},
			},
			wantErr: true,
			errMsg:  "web applications not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := f.Create("test-scanner", tt.config, tt.targets)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, s)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, s)
				assert.Equal(t, "test-scanner", s.Name())
			}
		})
	}
}

func TestScanner_Name(t *testing.T) {
	s := &Scanner{name: "test-trivy"}
	assert.Equal(t, "test-trivy", s.Name())
}

func TestScanner_Scan_AlreadyScanning(t *testing.T) {
	s := &Scanner{
		name:     "test",
		scanning: true,
		config:   DefaultConfig(),
		targets:  scanner.Targets{Images: []scanner.Image{{Name: "test"}}},
	}

	ctx := context.Background()
	findings, err := s.Scan(ctx)

	assert.Error(t, err)
	assert.Equal(t, scanner.ErrScanInProgress, err)
	assert.Nil(t, findings)
}

func TestScanner_Close(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Scanner{
		cancel: cancel,
	}

	err := s.Close()
	assert.NoError(t, err)

	// Verify context was canceled
	select {
	case <-ctx.Done():
		// Good, context was canceled
	default:
		t.Fatal("context was not canceled")
	}
}

func TestGenerateFindingID(t *testing.T) {
	// Test that IDs are deterministic
	id1 := generateFindingID("trivy", "vulnerability", "nginx:latest", "CVE-2021-1234", "libssl")
	id2 := generateFindingID("trivy", "vulnerability", "nginx:latest", "CVE-2021-1234", "libssl")
	assert.Equal(t, id1, id2, "IDs should be deterministic")

	// Test that different inputs produce different IDs
	id3 := generateFindingID("trivy", "vulnerability", "nginx:latest", "CVE-2021-5678", "libssl")
	assert.NotEqual(t, id1, id3, "Different CVEs should produce different IDs")

	// Test ID format
	assert.Equal(t, 16, len(id1), "ID should be 16 characters")
	assert.True(t, isHex(id1), "ID should be hexadecimal")
}

func TestCreateVulnerabilityFinding(t *testing.T) {
	s := &Scanner{name: "trivy"}

	vuln := TrivyVulnerability{
		VulnerabilityID:  "CVE-2021-1234",
		PkgName:          "openssl",
		InstalledVersion: "1.0.0",
		FixedVersion:     "1.0.1",
		Severity:         "HIGH",
		Title:            "OpenSSL vulnerability",
		Description:      "A serious vulnerability in OpenSSL",
		PrimaryURL:       "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1234",
		References:       []string{"https://example.com/advisory"},
		CweIDs:           []string{"CWE-79"},
		PublishedDate:    &time.Time{},
		CVSS: map[string]CVSSInfo{
			"nvd": {
				V3Score:  7.5,
				V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			},
		},
	}

	result := TrivyTargetResult{
		Target: "nginx:latest (debian 11.5)",
		Class:  "os-pkgs",
		Type:   "debian",
	}

	finding := s.createVulnerabilityFinding(vuln, result, "nginx:latest")

	assert.NotNil(t, finding)
	assert.Equal(t, "trivy", finding.Scanner)
	assert.Equal(t, "vulnerability", finding.Type)
	assert.Equal(t, "high", finding.Severity)
	// Since we set vuln.Title, it should use that directly
	assert.Equal(t, "OpenSSL vulnerability", finding.Title)
	assert.Equal(t, "A serious vulnerability in OpenSSL", finding.Description)
	assert.Contains(t, finding.Remediation, "Update openssl to version 1.0.1")
	assert.Equal(t, "nginx:latest", finding.Resource)
	assert.Equal(t, "nginx:latest (debian 11.5)", finding.Location)
	assert.Contains(t, finding.References, "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1234")
	assert.Contains(t, finding.References, "https://example.com/advisory")

	// Check metadata
	assert.Equal(t, "CVE-2021-1234", finding.Metadata["cve"])
	assert.Equal(t, "openssl", finding.Metadata["package"])
	assert.Equal(t, "1.0.0", finding.Metadata["version"])
	assert.Equal(t, "1.0.1", finding.Metadata["fixed_version"])

	// Check technical details
	var technical TrivyTechnical
	err := json.Unmarshal([]byte(finding.Metadata["technical_details"]), &technical)
	require.NoError(t, err)
	assert.Equal(t, "vuln", technical.ScannerType)
	assert.Equal(t, "CVE-2021-1234", technical.CVE)
	assert.Equal(t, []string{"CWE-79"}, technical.CWE)
	assert.Equal(t, float32(7.5), technical.CVSS.V3Score)
}

func TestCreateMisconfigurationFinding(t *testing.T) {
	s := &Scanner{name: "trivy"}

	misconf := TrivyMisconfiguration{
		Type:        "Kubernetes Security Check",
		ID:          "KSV012",
		Title:       "Containers should not run as root",
		Description: "Running containers as root user can pose security risks",
		Message:     "Container 'app' of Deployment 'web' should set 'securityContext.runAsNonRoot' to true",
		Resolution:  "Set 'securityContext.runAsNonRoot' to true",
		Severity:    "MEDIUM",
		PrimaryURL:  "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
		References:  []string{"https://example.com/k8s-security"},
		CauseMetadata: &TrivyCauseMetadata{
			StartLine: 25,
			EndLine:   30,
		},
	}

	result := TrivyTargetResult{
		Target: "deployment.yaml",
		Class:  "config",
		Type:   "kubernetes",
	}

	finding := s.createMisconfigurationFinding(misconf, result, "k8s-manifests")

	assert.NotNil(t, finding)
	assert.Equal(t, "trivy", finding.Scanner)
	assert.Equal(t, "misconfiguration", finding.Type)
	assert.Equal(t, "medium", finding.Severity)
	assert.Equal(t, "Containers should not run as root", finding.Title)
	assert.Equal(t, "Running containers as root user can pose security risks", finding.Description)
	assert.Equal(t, "Set 'securityContext.runAsNonRoot' to true", finding.Remediation)
	assert.Equal(t, "k8s-manifests", finding.Resource)
	assert.Equal(t, "deployment.yaml:25", finding.Location)
	assert.Contains(t, finding.References, "https://kubernetes.io/docs/concepts/security/pod-security-standards/")

	// Check metadata
	assert.Equal(t, "KSV012", finding.Metadata["check_id"])
	assert.Equal(t, "Kubernetes Security Check", finding.Metadata["check_type"])
	assert.Equal(t, "deployment.yaml", finding.Metadata["file"])
	assert.Equal(t, "25", finding.Metadata["line"])
}

func TestCreateSecretFinding(t *testing.T) {
	s := &Scanner{name: "trivy"}

	secret := TrivySecret{
		RuleID:    "aws-access-key-id",
		Category:  "AWS",
		Severity:  "CRITICAL",
		Title:     "AWS Access Key ID",
		StartLine: 42,
		EndLine:   42,
		Match:     "AKIAIOSFODNN7EXAMPLE",
	}

	result := TrivyTargetResult{
		Target: "config/app.conf",
		Class:  "secret",
	}

	finding := s.createSecretFinding(secret, result, "/app")

	assert.NotNil(t, finding)
	assert.Equal(t, "trivy", finding.Scanner)
	assert.Equal(t, "secret", finding.Type)
	assert.Equal(t, "critical", finding.Severity)
	assert.Equal(t, "Exposed AWS Access Key ID", finding.Title)
	assert.Contains(t, finding.Description, "Found AWS Access Key ID at line 42")
	assert.Equal(t, "Remove the secret from the codebase and rotate it immediately", finding.Remediation)
	assert.Equal(t, "/app", finding.Resource)
	assert.Equal(t, "config/app.conf:42", finding.Location)

	// Check metadata
	assert.Equal(t, "aws-access-key-id", finding.Metadata["rule_id"])
	assert.Equal(t, "AWS", finding.Metadata["secret_type"])
	assert.Equal(t, "config/app.conf", finding.Metadata["file"])
	assert.Equal(t, "42", finding.Metadata["line"])
}

func TestProcessResults(t *testing.T) {
	s := &Scanner{name: "trivy"}
	ctx := context.Background()
	findings := make(chan scanner.Finding, 10)

	result := &TrivyResult{
		SchemaVersion: 2,
		ArtifactName:  "nginx:latest",
		ArtifactType:  "container_image",
		Results: []TrivyTargetResult{
			{
				Target: "nginx:latest (debian 11.5)",
				Class:  "os-pkgs",
				Type:   "debian",
				Vulnerabilities: []TrivyVulnerability{
					{
						VulnerabilityID:  "CVE-2021-1234",
						PkgName:          "openssl",
						InstalledVersion: "1.0.0",
						FixedVersion:     "1.0.1",
						Severity:         "HIGH",
					},
				},
				Misconfigurations: []TrivyMisconfiguration{
					{
						ID:       "DS002",
						Title:    "Image user should not be root",
						Severity: "MEDIUM",
					},
				},
				Secrets: []TrivySecret{
					{
						RuleID:    "generic-api-key",
						Category:  "Generic",
						Severity:  "HIGH",
						Title:     "Generic API Key",
						StartLine: 10,
					},
				},
			},
		},
	}

	// Process results
	go func() {
		s.processResults(ctx, result, "image", "nginx:latest", findings)
		close(findings)
	}()

	// Collect findings
	collectedFindings := make([]scanner.Finding, 0, 3)
	for f := range findings {
		collectedFindings = append(collectedFindings, f)
	}

	// Should have 3 findings (1 vuln, 1 misconfig, 1 secret)
	assert.Len(t, collectedFindings, 3)

	// Check that we have one of each type
	types := make(map[string]int)
	for _, f := range collectedFindings {
		require.NotNil(t, f.Finding)
		types[f.Finding.Type]++
	}

	assert.Equal(t, 1, types["vulnerability"])
	assert.Equal(t, 1, types["misconfiguration"])
	assert.Equal(t, 1, types["secret"])
}

// Helper function to check if a string is hexadecimal.
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func TestValidateTargets(t *testing.T) {
	tests := []struct {
		name    string
		errMsg  string
		targets scanner.Targets
		wantErr bool
	}{
		{
			name: "valid image targets",
			targets: scanner.Targets{
				Images: []scanner.Image{{Name: "nginx:latest"}},
			},
			wantErr: false,
		},
		{
			name: "valid filesystem targets",
			targets: scanner.Targets{
				Filesystems: []scanner.Filesystem{{Path: "/app"}},
			},
			wantErr: false,
		},
		{
			name: "valid repository targets",
			targets: scanner.Targets{
				Repositories: []scanner.Repository{{Path: "/repo"}},
			},
			wantErr: false,
		},
		{
			name: "valid kubernetes targets",
			targets: scanner.Targets{
				KubernetesClusters: []scanner.KubernetesCluster{{Context: "default"}},
			},
			wantErr: false,
		},
		{
			name:    "no targets",
			targets: scanner.Targets{},
			wantErr: true,
			errMsg:  "no targets configured",
		},
		{
			name: "unsupported cloud targets",
			targets: scanner.Targets{
				CloudAccounts: []scanner.CloudAccount{{Provider: "aws"}},
			},
			wantErr: true,
			errMsg:  "cloud accounts not supported",
		},
		{
			name: "unsupported web targets",
			targets: scanner.Targets{
				WebApplications: []scanner.WebApplication{{URL: "https://example.com"}},
			},
			wantErr: true,
			errMsg:  "web applications not supported",
		},
		{
			name: "mixed valid and invalid targets",
			targets: scanner.Targets{
				Images:        []scanner.Image{{Name: "nginx"}},
				CloudAccounts: []scanner.CloudAccount{{Provider: "aws"}},
			},
			wantErr: true,
			errMsg:  "cloud accounts not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTargets(tt.targets)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTrivyTechnical_JSON(t *testing.T) {
	// Test that TrivyTechnical can be marshaled and unmarshaled
	tech := &TrivyTechnical{
		ScannerType:      "vuln",
		Target:           "nginx:latest",
		CVE:              "CVE-2021-1234",
		Package:          "openssl",
		InstalledVersion: "1.0.0",
		FixedVersion:     "1.0.1",
		CVSS: CVSSDetails{
			V3Score:  7.5,
			V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		},
		Lines: []LineInfo{
			{Start: 10, End: 20},
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(tech)
	require.NoError(t, err)

	// Unmarshal back
	var decoded TrivyTechnical
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify fields
	assert.Equal(t, tech.ScannerType, decoded.ScannerType)
	assert.Equal(t, tech.CVE, decoded.CVE)
	assert.Equal(t, tech.CVSS.V3Score, decoded.CVSS.V3Score)
	assert.Len(t, decoded.Lines, 1)
}

func TestSeverityNormalization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", "critical"},
		{"HIGH", "high"},
		{"MEDIUM", "medium"},
		{"LOW", "low"},
		{"UNKNOWN", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			// Test in createVulnerabilityFinding
			s := &Scanner{name: "trivy"}
			finding := s.createVulnerabilityFinding(
				TrivyVulnerability{
					VulnerabilityID: "TEST-001",
					PkgName:         "test",
					Severity:        tt.input,
				},
				TrivyTargetResult{Target: "test"},
				"test",
			)
			assert.Equal(t, tt.expected, finding.Severity)
		})
	}
}
