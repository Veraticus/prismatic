package scanner

import (
	"testing"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckovScanner_ParseRealOutput tests parsing of actual Checkov output.
// Test data is generated from real Checkov scans - see scripts/test/generate-checkov-testdata.sh.
func TestCheckovScanner_ParseRealOutput(t *testing.T) {
	scanner := NewCheckovScanner(Config{}, []string{"."})

	tests := []struct {
		validate      func(t *testing.T, findings []models.Finding)
		name          string
		input         string
		expectedCount int
	}{
		{
			name: "Real Terraform IAM privilege escalation - ACTUAL Checkov output with all 28 fields",
			input: `{
				"check_type": "terraform",
				"results": {
					"failed_checks": [
						{
							"bc_category": null,
							"bc_check_id": "BC_AWS_IAM_81",
							"benchmarks": null,
							"caller_file_line_range": null,
							"caller_file_path": null,
							"check_class": "checkov.terraform.checks.resource.aws.IAMPrivilegeEscalation",
							"check_id": "CKV_AWS_286",
							"check_len": null,
							"check_name": "Ensure IAM policies does not allow privilege escalation",
							"check_result": {
								"evaluated_keys": [
									"policy/Statement/[0]/Action"
								],
								"result": "FAILED"
							},
							"code_block": null,
							"connected_node": null,
							"definition_context_file_path": "/tmp/tmp.j2EqJaurgw/iam.tf",
							"description": null,
							"details": [],
							"entity_tags": null,
							"evaluations": null,
							"file_abs_path": "/tmp/tmp.j2EqJaurgw/iam.tf",
							"file_line_range": [
								1,
								15
							],
							"file_path": "/iam.tf",
							"fixed_definition": null,
							"guideline": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-iam-policies/bc-aws-286",
							"repo_file_path": "/tmp/tmp.j2EqJaurgw/iam.tf",
							"resource": "aws_iam_policy.admin_policy",
							"resource_address": null,
							"severity": null,
							"short_description": null,
							"vulnerability_details": null
						}
					]
				},
				"summary": {
					"checkov_version": "3.2.436",
					"failed": 31,
					"parsing_errors": 0,
					"passed": 12,
					"resource_count": 6,
					"skipped": 0
				}
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "checkov", f.Scanner)
				assert.Equal(t, "aws-misconfiguration", f.Type)    // CKV_AWS_286 doesn't have _IAM in name
				assert.Equal(t, models.SeverityMedium, f.Severity) // Default when null
				assert.Contains(t, f.Title, "IAM policies does not allow privilege escalation")
				assert.Equal(t, "CKV_AWS_286", f.Metadata["check_id"])

				// Verify parser handles real fields correctly
				// Note: bc_check_id is not stored in metadata currently
				assert.Equal(t, "checkov.terraform.checks.resource.aws.IAMPrivilegeEscalation", f.Metadata["check_class"])
			},
		},
		{
			name: "Real S3 bucket versioning - array format with actual Checkov output",
			input: `[{
				"check_type": "terraform",
				"results": {
					"failed_checks": [{
						"bc_category": null,
						"bc_check_id": "BC_AWS_S3_17",
						"benchmarks": null,
						"caller_file_line_range": null,
						"caller_file_path": null,
						"check_class": "checkov.terraform.checks.resource.aws.S3Versioning",
						"check_id": "CKV_AWS_21",
						"check_len": null,
						"check_name": "Ensure all data stored in the S3 bucket have versioning enabled",
						"check_result": {
							"evaluated_keys": [],
							"result": "FAILED"
						},
						"code_block": null,
						"connected_node": null,
						"definition_context_file_path": "/tmp/tmp.j2EqJaurgw/s3.tf",
						"description": null,
						"details": [],
						"entity_tags": null,
						"evaluations": null,
						"file_abs_path": "/tmp/tmp.j2EqJaurgw/s3.tf",
						"file_line_range": [1, 4],
						"file_path": "/s3.tf",
						"fixed_definition": null,
						"guideline": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/s3-policies/s3-16-enable-versioning",
						"repo_file_path": "/tmp/tmp.j2EqJaurgw/s3.tf",
						"resource": "aws_s3_bucket.insecure",
						"resource_address": null,
						"severity": null,
						"short_description": null,
						"vulnerability_details": null
					}]
				},
				"summary": {
					"checkov_version": "3.2.436",
					"failed": 31,
					"parsing_errors": 0,
					"passed": 12,
					"resource_count": 6,
					"skipped": 0
				}
			}]`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "checkov", f.Scanner)
				assert.Equal(t, "encryption-misconfiguration", f.Type) // Versioning = encryption type
				assert.Equal(t, models.SeverityMedium, f.Severity)
				assert.Contains(t, f.Title, "S3 bucket have versioning enabled")
				assert.Equal(t, "CKV_AWS_21", f.Metadata["check_id"])
			},
		},
		{
			name: "Real security group SSH exposure - actual Checkov output",
			input: `{
				"check_type": "terraform",
				"results": {
					"failed_checks": [{
						"bc_category": null,
						"bc_check_id": "BC_AWS_NETWORKING_1",
						"benchmarks": null,
						"caller_file_line_range": null,
						"caller_file_path": null,
						"check_class": "checkov.terraform.checks.resource.aws.SecurityGroupUnrestrictedIngress22",
						"check_id": "CKV_AWS_24",
						"check_len": null,
						"check_name": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
						"check_result": {
							"evaluated_keys": [
								"ingress/[0]/from_port",
								"ingress/[0]/to_port",
								"ingress/[0]/cidr_blocks"
							],
							"result": "FAILED"
						},
						"code_block": null,
						"connected_node": null,
						"definition_context_file_path": "/tmp/tmp.j2EqJaurgw/security_group.tf",
						"description": null,
						"details": [],
						"entity_tags": null,
						"evaluations": null,
						"file_abs_path": "/tmp/tmp.j2EqJaurgw/security_group.tf",
						"file_line_range": [6, 17],
						"file_path": "/security_group.tf",
						"fixed_definition": null,
						"guideline": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-networking-policies/networking-1-port-security",
						"repo_file_path": "/tmp/tmp.j2EqJaurgw/security_group.tf",
						"resource": "aws_security_group.allow_ssh",
						"resource_address": null,
						"severity": null,
						"short_description": null,
						"vulnerability_details": null
					}]
				},
				"summary": {
					"checkov_version": "3.2.436",
					"failed": 2,
					"parsing_errors": 0,
					"passed": 0,
					"resource_count": 1,
					"skipped": 0
				}
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "network-misconfiguration", f.Type)
				assert.Equal(t, models.SeverityMedium, f.Severity) // Default when null
				assert.Contains(t, f.Title, "security groups")
			},
		},
		{
			name: "IAM policy misconfiguration",
			input: `{
				"check_type": "terraform",
				"results": {
					"failed_checks": [{
						"check_id": "CKV_AWS_40",
						"check_name": "Ensure IAM policies are attached only to groups or roles",
						"severity": "MEDIUM",
						"file_path": "/iam.tf",
						"file_line_range": [20, 30],
						"resource": "aws_iam_user_policy.developer"
					}]
				},
				"summary": {"passed": 0, "failed": 1, "skipped": 0}
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "access-control-misconfiguration", f.Type)
			},
		},
		{
			name: "Encryption misconfiguration",
			input: `{
				"check_type": "terraform",
				"results": {
					"failed_checks": [{
						"check_id": "CKV_AWS_19",
						"check_name": "Ensure all data stored in the S3 bucket is securely encrypted at rest",
						"severity": "HIGH",
						"file_path": "/storage.tf",
						"file_line_range": [5, 10],
						"resource": "aws_s3_bucket.data"
					}]
				},
				"summary": {"passed": 0, "failed": 1, "skipped": 0}
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "encryption-misconfiguration", f.Type)
				assert.Equal(t, models.SeverityHigh, f.Severity)
			},
		},
		{
			name: "Dockerfile issues",
			input: `{
				"check_type": "dockerfile",
				"results": {
					"failed_checks": [{
						"check_id": "CKV_DOCKER_2",
						"check_name": "Ensure that HEALTHCHECK instruction have been added to container images",
						"check_result": {"result": "FAILED"},
						"file_path": "/Dockerfile",
						"file_line_range": [1, 15],
						"resource": "/Dockerfile",
						"severity": "LOW"
					}]
				},
				"summary": {"passed": 0, "failed": 1, "skipped": 0}
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "container-misconfiguration", f.Type)
				assert.Equal(t, models.SeverityLow, f.Severity)
			},
		},
		{
			name: "Kubernetes misconfiguration",
			input: `{
				"check_type": "kubernetes",
				"results": {
					"failed_checks": [{
						"check_id": "CKV_K8S_21",
						"check_name": "Ensure that the admission control plugin PodSecurityPolicy is set",
						"check_result": {"result": "FAILED"},
						"file_path": "/deployment.yaml",
						"file_line_range": [1, 30],
						"resource": "Deployment.default.nginx",
						"severity": "HIGH"
					}]
				},
				"summary": {"passed": 0, "failed": 1, "skipped": 0}
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "kubernetes-misconfiguration", f.Type)
			},
		},
		{
			name: "Multiple reports in array",
			input: `[
				{
					"check_type": "terraform",
					"results": {
						"failed_checks": [{
							"check_id": "CKV_AWS_145",
							"check_name": "Ensure that S3 buckets are encrypted with KMS by default",
							"severity": "HIGH",
							"file_path": "/s3.tf",
							"file_line_range": [1, 4],
							"resource": "aws_s3_bucket.test"
						}]
					},
					"summary": {"passed": 0, "failed": 1, "skipped": 0}
				},
				{
					"check_type": "terraform_plan",
					"results": {
						"failed_checks": []
					},
					"summary": {"passed": 0, "failed": 0, "skipped": 0}
				}
			]`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "aws-misconfiguration", f.Type)
				assert.Contains(t, f.Title, "encrypted with KMS")
			},
		},
		{
			name: "Null severity should default",
			input: `{
				"check_type": "terraform",
				"results": {
					"failed_checks": [{
						"check_id": "CKV_AWS_144",
						"check_name": "Ensure that S3 bucket has cross-region replication enabled",
						"file_path": "/s3.tf",
						"file_line_range": [1, 4],
						"resource": "aws_s3_bucket.test",
						"severity": null
					}]
				},
				"summary": {"passed": 0, "failed": 1, "skipped": 0}
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, models.SeverityMedium, f.Severity)
			},
		},
		{
			name: "Secrets detection",
			input: `{
				"check_type": "secrets",
				"results": {
					"failed_checks": []
				},
				"secrets_failed_checks": [{
					"check_id": "CKV_SECRET_6",
					"check_name": "Base64 High Entropy String",
					"file_path": "/config.yaml",
					"line_number": 42,
					"secret_type": "Base64 High Entropy String"
				}],
				"summary": {"passed": 0, "failed": 1, "skipped": 0}
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "exposed-secret", f.Type)
				assert.Equal(t, models.SeverityHigh, f.Severity)
				assert.Contains(t, f.Title, "Base64 High Entropy String")
			},
		},
		{
			name:          "Empty results",
			input:         `{"check_type": "terraform", "results": {"failed_checks": []}, "summary": {"passed": 1, "failed": 0}}`,
			expectedCount: 0,
		},
		{
			name:          "Invalid JSON",
			input:         `{invalid json`,
			expectedCount: -1, // Expect error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := scanner.ParseResults([]byte(tt.input))

			if tt.expectedCount == -1 {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, findings, tt.expectedCount)

			if tt.validate != nil && len(findings) > 0 {
				tt.validate(t, findings)
			}
		})
	}
}

func TestCheckovScanner_mapCheckIDToType(t *testing.T) {
	scanner := NewCheckovScanner(Config{}, []string{"."})

	tests := []struct {
		checkID  string
		expected string
	}{
		// AWS specific checks
		{"CKV_AWS_123", "aws-misconfiguration"},
		{"CKV_AWS_19", "encryption-misconfiguration"},
		{"CKV_AWS_21", "encryption-misconfiguration"},
		{"CKV_AWS_40", "access-control-misconfiguration"},
		{"CKV_AWS_61", "access-control-misconfiguration"},
		{"CKV_AWS_62", "access-control-misconfiguration"},
		{"CKV_AWS_24", "network-misconfiguration"},
		{"CKV_AWS_25", "network-misconfiguration"},

		// Other cloud providers
		{"CKV_AZURE_45", "azure-misconfiguration"},
		{"CKV_GCP_67", "gcp-misconfiguration"},

		// Technology specific
		{"CKV_K8S_89", "kubernetes-misconfiguration"},
		{"CKV_DOCKER_12", "container-misconfiguration"},
		{"CKV_GIT_3", "git-misconfiguration"},
		{"CKV_SECRET_6", "exposed-secret"},

		// Pattern based
		{"CKV_AWS_145_ENCRYPT", "encryption-misconfiguration"},
		{"CKV_AWS_100_LOGGING", "logging-misconfiguration"},
		{"CKV_AWS_50_IAM", "access-control-misconfiguration"},
		{"CKV_AWS_88_NETWORK", "network-misconfiguration"},

		// Default
		{"CKV_CUSTOM_123", "iac-misconfiguration"},
		{"UNKNOWN_CHECK", "iac-misconfiguration"},
	}

	for _, tt := range tests {
		t.Run(tt.checkID, func(t *testing.T) {
			result := scanner.mapCheckIDToType(tt.checkID)
			assert.Equal(t, tt.expected, result)
		})
	}
}
