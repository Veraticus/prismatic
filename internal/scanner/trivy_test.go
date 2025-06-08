package scanner

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrivyScanner_ParseResults(t *testing.T) {
	scanner := NewTrivyScanner(Config{}, []string{"test-image"})

	tests := []struct {
		validate func(t *testing.T, findings []models.Finding)
		name     string
		input    string
		expected int
	}{
		{
			name: "vulnerability findings",
			input: `{
				"ArtifactName": "alpine:3.18",
				"Results": [{
					"Target": "alpine:3.18",
					"Type": "os-pkgs",
					"Vulnerabilities": [{
						"VulnerabilityID": "CVE-2023-12345",
						"PkgName": "openssl",
						"InstalledVersion": "1.1.1t",
						"FixedVersion": "1.1.1u",
						"Severity": "HIGH",
						"Description": "OpenSSL vulnerability",
						"PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
						"CVSS": {
							"nvd": {
								"V3Score": 7.5
							}
						}
					}]
				}]
			}`,
			expected: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				finding := findings[0]
				assert.Equal(t, "vulnerability", finding.Type)
				assert.Equal(t, "high", finding.Severity)
				assert.Equal(t, "alpine:3.18", finding.Resource)
				assert.Contains(t, finding.Title, "CVE-2023-12345")
				assert.Contains(t, finding.Remediation, "Update openssl to version 1.1.1u")
				assert.Equal(t, "1.1.1t", finding.Metadata["installed_version"])
			},
		},
		{
			name: "misconfiguration findings",
			input: `{
				"Results": [{
					"Target": "Dockerfile",
					"Type": "dockerfile",
					"Misconfigurations": [{
						"Type": "Dockerfile Security Check",
						"ID": "DS001",
						"Title": "User is not set",
						"Description": "Running as root is insecure",
						"Message": "Consider using USER instruction",
						"Resolution": "Add USER instruction to Dockerfile",
						"Severity": "MEDIUM",
						"PrimaryURL": "https://avd.aquasec.com/ds001",
						"StartLine": 10,
						"EndLine": 10
					}]
				}]
			}`,
			expected: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				finding := findings[0]
				assert.Equal(t, "misconfiguration", finding.Type)
				assert.Equal(t, "medium", finding.Severity)
				assert.Equal(t, "Dockerfile", finding.Resource)
				assert.Equal(t, "User is not set", finding.Title)
				assert.Equal(t, "10", finding.Metadata["start_line"])
			},
		},
		{
			name: "secret findings",
			input: `{
				"Results": [{
					"Target": "config.yaml",
					"Type": "secret",
					"Secrets": [{
						"RuleID": "aws-secret-access-key",
						"Severity": "CRITICAL",
						"Title": "AWS Secret Access Key",
						"Target": "config.yaml",
						"StartLine": 15,
						"EndLine": 15,
						"Match": "aws_secret_access_key = AKIAIOSFODNN7EXAMPLE"
					}]
				}]
			}`,
			expected: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				finding := findings[0]
				assert.Equal(t, "secret", finding.Type)
				assert.Equal(t, "critical", finding.Severity)
				assert.Equal(t, "config.yaml", finding.Resource)
				assert.Contains(t, finding.Title, "AWS Secret Access Key")
				assert.Contains(t, finding.Remediation, "rotate it immediately")
			},
		},
		{
			name: "multiple findings",
			input: `{
				"Results": [{
					"Target": "test",
					"Vulnerabilities": [
						{"VulnerabilityID": "CVE-1", "PkgName": "pkg1", "Severity": "HIGH"},
						{"VulnerabilityID": "CVE-2", "PkgName": "pkg2", "Severity": "LOW"}
					],
					"Misconfigurations": [
						{"ID": "M1", "Title": "Misconfig 1", "Severity": "MEDIUM", "StartLine": 1}
					]
				}]
			}`,
			expected: 3,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				assert.Len(t, findings, 3)

				// Check we have different types
				types := make(map[string]int)
				for _, f := range findings {
					types[f.Type]++
				}
				assert.Equal(t, 2, types["vulnerability"])
				assert.Equal(t, 1, types["misconfiguration"])
			},
		},
		{
			name: "vulnerability with published date",
			input: `{
				"Results": [{
					"Target": "test:latest",
					"Type": "os-pkgs",
					"Vulnerabilities": [{
						"VulnerabilityID": "CVE-2023-45678",
						"PkgName": "libssl",
						"InstalledVersion": "1.0.2k",
						"FixedVersion": "1.0.2l",
						"Severity": "CRITICAL",
						"Description": "SSL vulnerability",
						"PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-45678",
						"PublishedDate": "2023-06-15T10:30:00Z",
						"LastModifiedDate": "2023-06-16T12:00:00Z"
					},{
						"VulnerabilityID": "CVE-2023-45679",
						"PkgName": "libssl2",
						"Severity": "HIGH",
						"PublishedDate": "2023-06-15T10:30:00.123Z"
					}]
				}]
			}`,
			expected: 2,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				// First finding with RFC3339 date
				finding1 := findings[0]
				assert.False(t, finding1.PublishedDate.IsZero())
				assert.Equal(t, "2023-06-15T10:30:00Z", finding1.Metadata["published_date"])
				assert.Equal(t, "2023-06-16T12:00:00Z", finding1.Metadata["last_modified_date"])

				// Second finding with fractional seconds
				finding2 := findings[1]
				assert.False(t, finding2.PublishedDate.IsZero())
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

func TestTrivyScanner_ParseResults_InvalidJSON(t *testing.T) {
	scanner := NewTrivyScanner(Config{}, []string{})

	_, err := scanner.ParseResults([]byte("invalid json"))
	assert.Error(t, err)
	assert.IsType(t, &Error{}, err)
}

func TestTrivyScanner_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Check if Trivy is installed
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("Trivy not found in PATH, skipping integration test")
	}

	// This test requires Trivy to be installed
	scanner := NewTrivyScanner(
		Config{Debug: true},
		[]string{"alpine:3.18"},
	)

	ctx := context.Background()
	result, err := scanner.Scan(ctx)

	require.NoError(t, err)
	assert.Equal(t, "trivy", result.Scanner)
	assert.NotZero(t, result.StartTime)
	assert.NotZero(t, result.EndTime)

	// Alpine 3.18 should have some known vulnerabilities
	assert.NotEmpty(t, result.Findings)
}

func TestTrivyReport_ComplexStructure(t *testing.T) {
	// Test that our struct definitions correctly parse complex Trivy output
	complexReport := `{
		"ArtifactName": "test:latest",
		"ArtifactType": "container_image",
		"Results": [{
			"Target": "test:latest (debian 11.7)",
			"Type": "os-pkgs",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2023-1234",
				"PkgName": "libc6",
				"InstalledVersion": "2.31-13",
				"FixedVersion": "2.31-14",
				"Severity": "HIGH",
				"Description": "Buffer overflow in libc",
				"PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
				"References": [
					"https://debian.org/security/2023/dsa-5432",
					"https://ubuntu.com/security/CVE-2023-1234"
				],
				"CVSS": {
					"nvd": {
						"V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
						"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						"V2Score": 7.5,
						"V3Score": 9.8
					}
				}
			}]
		}]
	}`

	var report TrivyReport
	err := json.Unmarshal([]byte(complexReport), &report)
	require.NoError(t, err)

	assert.Equal(t, "test:latest", report.ArtifactName)
	assert.Len(t, report.Results, 1)
	assert.Len(t, report.Results[0].Vulnerabilities, 1)

	vuln := report.Results[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2023-1234", vuln.VulnerabilityID)
	assert.Len(t, vuln.References, 2)
	assert.NotNil(t, vuln.CVSS)
	if nvd, ok := vuln.CVSS["nvd"].(map[string]any); ok {
		assert.Equal(t, 9.8, nvd["V3Score"])
	} else {
		t.Error("Expected CVSS nvd to be a map[string]any")
	}
}
