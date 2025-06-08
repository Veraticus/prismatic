package scanner

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckovScanner_ParseResults(t *testing.T) {
	scanner := NewCheckovScanner(Config{}, []string{"."})

	tests := []struct {
		validateFirst func(*testing.T, models.Finding)
		name          string
		input         string
		wantFindings  int
	}{
		{
			name: "terraform AWS misconfiguration",
			input: `{
				"check_type": "terraform",
				"results": {
					"terraform": {
						"check_type": "terraform",
						"failed_checks": [
							{
								"check_id": "CKV_AWS_23",
								"check_name": "Ensure every S3 bucket has a lifecycle configuration",
								"check_result": {"result": "FAILED"},
								"check_class": "checkov.terraform.checks.resource.aws.S3BucketLifecycleConfiguration",
								"code_block": "resource \"aws_s3_bucket\" \"example\" {\n  bucket = \"my-bucket\"\n}",
								"description": "S3 buckets should have lifecycle policies configured",
								"file_path": "/path/to/main.tf",
								"file_line_range": [10, 20],
								"resource": "aws_s3_bucket.example",
								"resource_address": "module.storage.aws_s3_bucket.example",
								"severity": "MEDIUM",
								"guideline": "https://docs.bridgecrew.io/docs/s3_16"
							}
						],
						"passed_checks": [],
						"skipped_checks": []
					}
				},
				"summary": {"passed": 0, "failed": 1, "skipped": 0}
			}`,
			wantFindings: 1,
			validateFirst: func(t *testing.T, f models.Finding) {
				t.Helper()
				assert.Equal(t, "checkov", f.Scanner)
				assert.Equal(t, "aws-misconfiguration", f.Type)
				assert.Equal(t, models.SeverityMedium, f.Severity)
				assert.Equal(t, "Ensure every S3 bucket has a lifecycle configuration", f.Title)
				assert.Contains(t, f.Resource, "main.tf")
				assert.Contains(t, f.Location, "aws_s3_bucket.example")
				assert.Contains(t, f.Location, "lines 10-20")
				assert.Equal(t, "CKV_AWS_23", f.Metadata["check_id"])
				assert.Equal(t, "terraform", f.Metadata["check_type"])
				assert.Contains(t, f.References[0], "bridgecrew.io")
			},
		},
		{
			name: "kubernetes misconfiguration",
			input: `{
				"check_type": "kubernetes",
				"results": {
					"kubernetes": {
						"check_type": "kubernetes",
						"failed_checks": [
							{
								"check_id": "CKV_K8S_21",
								"check_name": "Ensure that the admission control plugin PodSecurityPolicy is set",
								"check_result": {"result": "FAILED"},
								"check_class": "checkov.kubernetes.checks.resource.k8s.PodSecurityPolicy",
								"file_path": "/manifests/deployment.yaml",
								"file_line_range": [1, 30],
								"resource": "Deployment.default.nginx",
								"severity": "HIGH",
								"description": "Pod security policies should be enforced"
							}
						],
						"passed_checks": [],
						"skipped_checks": []
					}
				},
				"summary": {"passed": 0, "failed": 1, "skipped": 0}
			}`,
			wantFindings: 1,
			validateFirst: func(t *testing.T, f models.Finding) {
				t.Helper()
				assert.Equal(t, "kubernetes-misconfiguration", f.Type)
				assert.Equal(t, models.SeverityHigh, f.Severity)
				assert.Contains(t, f.Title, "PodSecurityPolicy")
				assert.Equal(t, "CKV_K8S_21", f.Metadata["check_id"])
			},
		},
		{
			name: "dockerfile misconfiguration",
			input: `{
				"check_type": "dockerfile",
				"results": {
					"dockerfile": {
						"check_type": "dockerfile",
						"failed_checks": [
							{
								"check_id": "CKV_DOCKER_2",
								"check_name": "Ensure that HEALTHCHECK instruction have been added to container images",
								"check_result": {"result": "FAILED"},
								"file_path": "/app/Dockerfile",
								"file_line_range": [1, 15],
								"resource": "/app/Dockerfile",
								"severity": "LOW",
								"guideline": "https://docs.bridgecrew.io/docs/ensure-that-healthcheck-instruction-have-been-added-to-container-images"
							}
						],
						"passed_checks": [],
						"skipped_checks": []
					}
				},
				"summary": {"passed": 0, "failed": 1, "skipped": 0}
			}`,
			wantFindings: 1,
			validateFirst: func(t *testing.T, f models.Finding) {
				t.Helper()
				assert.Equal(t, "container-misconfiguration", f.Type)
				assert.Equal(t, models.SeverityLow, f.Severity)
				assert.Contains(t, f.Title, "HEALTHCHECK")
			},
		},
		{
			name: "exposed secrets",
			input: `{
				"check_type": "secrets",
				"results": {},
				"secrets_failed_checks": [
					{
						"check_id": "CKV_SECRET_6",
						"check_name": "Base64 High Entropy String",
						"file_path": "/config/app.yaml",
						"line_number": 42,
						"secret_type": "Base64 High Entropy String"
					}
				],
				"summary": {"passed": 0, "failed": 1, "skipped": 0}
			}`,
			wantFindings: 1,
			validateFirst: func(t *testing.T, f models.Finding) {
				t.Helper()
				assert.Equal(t, "exposed-secret", f.Type)
				assert.Equal(t, models.SeverityHigh, f.Severity)
				assert.Contains(t, f.Title, "Exposed Base64 High Entropy String")
				assert.Contains(t, f.Resource, "app.yaml")
				assert.Equal(t, "line 42", f.Location)
				assert.Equal(t, "42", f.Metadata["line_number"])
			},
		},
		{
			name: "multiple check types",
			input: `{
				"check_type": "all",
				"results": {
					"terraform": {
						"check_type": "terraform",
						"failed_checks": [
							{
								"check_id": "CKV_AWS_45",
								"check_name": "Ensure no hard-coded secrets exist in lambda environment",
								"severity": "CRITICAL",
								"file_path": "/terraform/lambda.tf",
								"file_line_range": [15, 20],
								"resource": "aws_lambda_function.api"
							}
						],
						"passed_checks": [],
						"skipped_checks": []
					},
					"dockerfile": {
						"check_type": "dockerfile",
						"failed_checks": [
							{
								"check_id": "CKV_DOCKER_3",
								"check_name": "Ensure that a user for the container has been created",
								"severity": "MEDIUM",
								"file_path": "/docker/api/Dockerfile",
								"file_line_range": [1, 50],
								"resource": "/docker/api/Dockerfile"
							}
						],
						"passed_checks": [],
						"skipped_checks": []
					}
				},
				"summary": {"passed": 0, "failed": 2, "skipped": 0}
			}`,
			wantFindings: 2,
			validateFirst: func(t *testing.T, f models.Finding) {
				t.Helper()
				// First finding should be terraform
				assert.Equal(t, "aws-misconfiguration", f.Type)
				assert.Equal(t, models.SeverityCritical, f.Severity)
			},
		},
		{
			name: "encryption misconfiguration",
			input: `{
				"check_type": "terraform",
				"results": {
					"terraform": {
						"check_type": "terraform",
						"failed_checks": [
							{
								"check_id": "CKV_AWS_19",
								"check_name": "Ensure all data stored in the S3 bucket is securely encrypted at rest",
								"severity": "HIGH",
								"file_path": "/terraform/storage.tf",
								"file_line_range": [5, 10],
								"resource": "aws_s3_bucket.data",
								"guideline": "https://docs.bridgecrew.io/docs/s3_14-data-encrypted-at-rest"
							}
						],
						"passed_checks": [],
						"skipped_checks": []
					}
				},
				"summary": {"passed": 0, "failed": 1, "skipped": 0}
			}`,
			wantFindings: 1,
			validateFirst: func(t *testing.T, f models.Finding) {
				t.Helper()
				assert.Equal(t, "encryption-misconfiguration", f.Type)
				assert.Contains(t, f.Title, "encrypted at rest")
			},
		},
		{
			name: "IAM misconfiguration",
			input: `{
				"check_type": "terraform",
				"results": {
					"terraform": {
						"check_type": "terraform",
						"failed_checks": [
							{
								"check_id": "CKV_AWS_40",
								"check_name": "Ensure IAM policies are attached only to groups or roles",
								"severity": "MEDIUM",
								"file_path": "/terraform/iam.tf",
								"file_line_range": [20, 30],
								"resource": "aws_iam_user_policy.developer"
							}
						],
						"passed_checks": [],
						"skipped_checks": []
					}
				},
				"summary": {"passed": 0, "failed": 1, "skipped": 0}
			}`,
			wantFindings: 1,
			validateFirst: func(t *testing.T, f models.Finding) {
				t.Helper()
				assert.Equal(t, "access-control-misconfiguration", f.Type)
			},
		},
		{
			name: "empty results",
			input: `{
				"check_type": "terraform",
				"results": {
					"terraform": {
						"check_type": "terraform",
						"failed_checks": [],
						"passed_checks": [{"check_id": "CKV_AWS_1"}],
						"skipped_checks": []
					}
				},
				"summary": {"passed": 1, "failed": 0, "skipped": 0}
			}`,
			wantFindings: 0,
		},
		{
			name:         "invalid JSON",
			input:        `{invalid json`,
			wantFindings: -1, // Expect error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := scanner.ParseResults([]byte(tt.input))

			if tt.wantFindings == -1 {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, findings, tt.wantFindings)

			if tt.wantFindings > 0 && tt.validateFirst != nil {
				tt.validateFirst(t, findings[0])
			}
		})
	}
}

func TestCheckovScanner_mapCheckIDToType(t *testing.T) {
	scanner := NewCheckovScanner(Config{}, []string{"."})

	tests := []struct {
		checkID  string
		wantType string
	}{
		{"CKV_AWS_123", "aws-misconfiguration"},
		{"CKV_AZURE_45", "azure-misconfiguration"},
		{"CKV_GCP_67", "gcp-misconfiguration"},
		{"CKV_K8S_89", "kubernetes-misconfiguration"},
		{"CKV_DOCKER_12", "container-misconfiguration"},
		{"CKV_GIT_3", "git-misconfiguration"},
		{"CKV_SECRET_6", "exposed-secret"},
		{"CKV_AWS_19_ENCRYPTION", "encryption-misconfiguration"},
		{"CKV_AWS_145_LOGGING", "logging-misconfiguration"},
		{"CKV_AWS_40_IAM", "access-control-misconfiguration"},
		{"CKV_AWS_NET_23", "network-misconfiguration"},
		{"CKV_CUSTOM_123", "iac-misconfiguration"},
	}

	for _, tt := range tests {
		t.Run(tt.checkID, func(t *testing.T) {
			got := scanner.mapCheckIDToType(tt.checkID)
			assert.Equal(t, tt.wantType, got)
		})
	}
}

func TestCheckovScanner_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Check if checkov is available
	if _, err := exec.LookPath("checkov"); err != nil {
		t.Skip("checkov not found in PATH")
	}

	// Create test directory with sample IaC files
	tmpDir, err := os.MkdirTemp("", "checkov-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a sample Terraform file with issues
	tfContent := `
resource "aws_s3_bucket" "insecure" {
  bucket = "my-insecure-bucket"
}

resource "aws_security_group" "wide_open" {
  name = "allow_all"
  
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
	err = os.WriteFile(tmpDir+"/main.tf", []byte(tfContent), 0600)
	require.NoError(t, err)

	// Create a sample Dockerfile with issues
	dockerContent := `FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
EXPOSE 8080
CMD ["bash"]
`
	err = os.WriteFile(tmpDir+"/Dockerfile", []byte(dockerContent), 0600)
	require.NoError(t, err)

	scanner := NewCheckovScanner(
		Config{
			WorkingDir: tmpDir,
			Debug:      true,
		},
		[]string{tmpDir},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "checkov", result.Scanner)
	assert.NotEqual(t, "unknown", result.Version)
	assert.NotEmpty(t, result.Findings)

	// Validate findings
	for _, finding := range result.Findings {
		assert.NotEmpty(t, finding.ID)
		assert.NotEmpty(t, finding.Type)
		assert.NotEmpty(t, finding.Title)
		assert.NotEmpty(t, finding.Resource)
		assert.NotEmpty(t, finding.Severity)
		assert.Contains(t, []string{
			models.SeverityInfo,
			models.SeverityLow,
			models.SeverityMedium,
			models.SeverityHigh,
			models.SeverityCritical,
		}, finding.Severity)
	}
}

func TestCheckovScanner_RealWorldJSON(t *testing.T) {
	scanner := NewCheckovScanner(Config{}, []string{"."})

	// Real-world Checkov output with various finding types
	realOutput := `{
		"check_type": "all",
		"results": {
			"terraform": {
				"check_type": "terraform",
				"failed_checks": [
					{
						"check_id": "CKV_AWS_18",
						"bc_check_id": "BC_AWS_S3_13",
						"check_name": "Ensure the S3 bucket has access logging enabled",
						"check_result": {
							"result": "FAILED",
							"evaluated_keys": ["access_logging_enabled"]
						},
						"code_block": [
							[1, "resource \"aws_s3_bucket\" \"data_bucket\" {\n"],
							[2, "  bucket = \"company-data-bucket\"\n"],
							[3, "  acl    = \"private\"\n"],
							[4, "}\n"]
						],
						"file_path": "/terraform/modules/storage/s3.tf",
						"file_abs_path": "/home/user/project/terraform/modules/storage/s3.tf",
						"repo_file_path": "/terraform/modules/storage/s3.tf",
						"file_line_range": [1, 4],
						"resource": "aws_s3_bucket.data_bucket",
						"evaluations": null,
						"check_class": "checkov.terraform.checks.resource.aws.S3AccessLogs",
						"fixed_definition": null,
						"entity_tags": null,
						"caller_file_path": null,
						"caller_file_line_range": null,
						"resource_address": "module.storage.aws_s3_bucket.data_bucket",
						"severity": "MEDIUM",
						"description": "Ensure the S3 bucket has access logging enabled",
						"short_description": "S3 Bucket has access logging enabled",
						"vulnerability_details": {
							"id": "CKV_AWS_18",
							"title": "Ensure the S3 bucket has access logging enabled",
							"guidelines": "https://docs.bridgecrew.io/docs/s3_13-enable-logging",
							"severity": "MEDIUM",
							"details": []
						},
						"connected_node": null,
						"guideline": "https://docs.bridgecrew.io/docs/s3_13-enable-logging",
						"details": [],
						"check_len": null,
						"definition_context_file_path": "/terraform/modules/storage/s3.tf",
						"breadcrumbs": null,
						"validation_status": null,
						"added_commit_hash": null,
						"removed_commit_hash": null
					}
				],
				"passed_checks": [],
				"skipped_checks": [],
				"parsing_errors": []
			},
			"secrets": {
				"check_type": "secrets",
				"failed_checks": [
					{
						"check_id": "CKV_SECRET_2",
						"bc_check_id": "BC_GIT_2",
						"check_name": "AWS Access Key",
						"check_result": {
							"result": "FAILED"
						},
						"code_block": [
							[15, "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"]
						],
						"file_path": "/config/aws.conf",
						"file_abs_path": "/home/user/project/config/aws.conf",
						"file_line_range": [15, 15],
						"resource": "4c104e8c8af577c4f68b3a929c546b5697d9b0b6",
						"check_class": "checkov.secrets.runner.CheckovSecretsRunner",
						"severity": "HIGH",
						"description": "AWS Access Key",
						"short_description": "AWS Access Key",
						"vulnerability_details": {
							"id": "CKV_SECRET_2",
							"title": "AWS Access Key",
							"severity": "HIGH"
						}
					}
				],
				"passed_checks": [],
				"skipped_checks": []
			}
		},
		"summary": {
			"passed": 45,
			"failed": 2,
			"skipped": 3,
			"parsing_errors": 0,
			"resource_count": 50,
			"checkov_version": "2.3.340"
		}
	}`

	findings, err := scanner.ParseResults([]byte(realOutput))
	require.NoError(t, err)
	assert.Len(t, findings, 2)

	// Find the S3 finding
	var s3Finding *models.Finding
	for i := range findings {
		if findings[i].Type == "aws-misconfiguration" {
			s3Finding = &findings[i]
			break
		}
	}

	if s3Finding != nil {
		assert.Equal(t, "aws-misconfiguration", s3Finding.Type)
		assert.Equal(t, models.SeverityMedium, s3Finding.Severity)
		assert.Contains(t, s3Finding.Title, "S3 bucket has access logging enabled")
		assert.Contains(t, s3Finding.Resource, "s3.tf")
		assert.Equal(t, "CKV_AWS_18", s3Finding.Metadata["check_id"])
		if len(s3Finding.References) > 0 {
			assert.Contains(t, s3Finding.References[0], "bridgecrew.io")
		}
	}

	// Check secret finding
	// There's only one finding in secrets.failed_checks, not in results
	// So the second finding would be from the secrets section
	assert.True(t, len(findings) >= 1)

	// Find the secret finding
	var secretFinding *models.Finding
	for i := range findings {
		if findings[i].Type == "exposed-secret" {
			secretFinding = &findings[i]
			break
		}
	}

	if secretFinding != nil {
		assert.Equal(t, "exposed-secret", secretFinding.Type)
		assert.Equal(t, models.SeverityHigh, secretFinding.Severity)
		assert.Contains(t, secretFinding.Title, "AWS Access Key")
		assert.Contains(t, secretFinding.Resource, "aws.conf")
	}
}

func TestCheckovScanner_getVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	if _, err := exec.LookPath("checkov"); err != nil {
		t.Skip("checkov not found in PATH")
	}

	scanner := NewCheckovScanner(Config{}, []string{"."})
	version := scanner.getVersion(context.Background())

	assert.NotEqual(t, "unknown", version)
	assert.NotEmpty(t, version)
}

func TestCheckovScanner_ContextCancellation(t *testing.T) {
	scanner := NewCheckovScanner(Config{}, []string{".", "/tmp", "/var"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := scanner.Scan(ctx)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Error, "scan canceled")
}

func TestCheckovScanner_ComplexCodeBlock(t *testing.T) {
	scanner := NewCheckovScanner(Config{}, []string{"."})

	input := `{
		"check_type": "terraform",
		"results": {
			"terraform": {
				"check_type": "terraform",
				"failed_checks": [
					{
						"check_id": "CKV_AWS_24",
						"check_name": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
						"code_block": "resource \"aws_security_group\" \"ssh\" {\n  name = \"allow_ssh\"\n  \n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}",
						"file_path": "/terraform/security.tf",
						"file_line_range": [10, 20],
						"resource": "aws_security_group.ssh",
						"severity": "HIGH",
						"description": "Security group allows unrestricted SSH access"
					}
				],
				"passed_checks": [],
				"skipped_checks": []
			}
		},
		"summary": {"passed": 0, "failed": 1, "skipped": 0}
	}`

	findings, err := scanner.ParseResults([]byte(input))
	require.NoError(t, err)
	assert.Len(t, findings, 1)

	finding := findings[0]
	assert.Equal(t, "network-misconfiguration", finding.Type)
	assert.Equal(t, models.SeverityHigh, finding.Severity)
	assert.NotEmpty(t, finding.Metadata["code_block"])
	assert.Contains(t, finding.Metadata["code_block"], "0.0.0.0/0")
}
