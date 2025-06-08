package scanner

import (
	"testing"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProwlerScanner_ParseResults(t *testing.T) {
	scanner := NewProwlerScanner(Config{}, []string{"default"}, []string{"us-east-1"}, nil)

	tests := []struct {
		validate func(t *testing.T, findings []models.Finding)
		name     string
		input    string
		expected int
	}{
		{
			name: "OCSF format findings",
			input: `[{
				"metadata": {
					"event_code": "s3_bucket_public_read_prohibited",
					"product": {
						"name": "Prowler",
						"version": "4.0.0"
					}
				},
				"severity_id": 4,
				"severity": "High",
				"status": "FAIL",
				"status_code": "FAIL",
				"status_detail": "S3 Bucket my-public-bucket allows public read access",
				"message": "Ensure S3 buckets do not allow public read access",
				"resources": [{
					"uid": "arn:aws:s3:::my-public-bucket",
					"type": "AwsS3Bucket",
					"region": "us-east-1"
				}],
				"finding": {
					"uid": "prowler-s3_bucket_public_read_prohibited-123456789012-us-east-1-abc123",
					"type": "internet-exposed",
					"title": "Ensure S3 buckets do not allow public read access",
					"desc": "S3 buckets should not allow public read access to prevent unauthorized data exposure",
					"service": "s3",
					"remediation": {
						"desc": "Remove public read permissions from the S3 bucket policy and ACLs",
						"references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"]
					}
				},
				"compliance": ["CIS-AWS-1.5-2.1.1", "NIST-800-53-AC-3"]
			}]`,
			expected: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				finding := findings[0]
				assert.Equal(t, "internet-exposed", finding.Type)
				assert.Equal(t, "high", finding.Severity)
				assert.Equal(t, "arn:aws:s3:::my-public-bucket", finding.Resource)
				assert.Contains(t, finding.Title, "S3 buckets do not allow public read")
				assert.Contains(t, finding.Remediation, "Remove public read permissions")
				assert.Equal(t, "s3_bucket_public_read_prohibited", finding.Metadata["check_id"])
				assert.Contains(t, finding.Metadata["compliance"], "CIS-AWS-1.5-2.1.1")
			},
		},
		{
			name: "Native format findings",
			input: `[{
				"Provider": "aws",
				"AccountId": "123456789012",
				"Region": "us-east-1",
				"CheckID": "iam_user_hardware_mfa_enabled",
				"CheckTitle": "Ensure hardware MFA is enabled for the root user",
				"ServiceName": "iam",
				"Status": "FAIL",
				"StatusExtended": "Root user does not have hardware MFA enabled",
				"Severity": "critical",
				"ResourceId": "root",
				"ResourceArn": "arn:aws:iam::123456789012:root",
				"ResourceType": "AwsIamUser",
				"Description": "The root user is the most privileged user in an AWS account",
				"Risk": "Without hardware MFA, the root account is vulnerable to compromise",
				"Remediation": {
					"Code": {
						"CLI": "aws iam enable-mfa-device --user-name root --serial-number <mfa-serial> --authentication-code1 <code1> --authentication-code2 <code2>"
					},
					"Recommendation": {
						"Text": "Enable hardware MFA for the root user to add an extra layer of protection",
						"Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa"
					}
				}
			}]`,
			expected: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				finding := findings[0]
				assert.Equal(t, "iam", finding.Type)
				assert.Equal(t, "critical", finding.Severity)
				assert.Equal(t, "arn:aws:iam::123456789012:root", finding.Resource)
				assert.Contains(t, finding.Title, "hardware MFA")
				assert.Contains(t, finding.Remediation, "Enable hardware MFA")
				assert.Contains(t, finding.Remediation, "aws iam enable-mfa-device")
				assert.Equal(t, "123456789012", finding.Metadata["account_id"])
			},
		},
		{
			name: "NDJSON format",
			input: `{"metadata":{"event_code":"ec2_instance_public_ip","product":{"name":"Prowler","version":"4.0.0"}},"severity":"Medium","status":"FAIL","resources":[{"uid":"arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0","type":"AwsEc2Instance","region":"us-east-1"}],"finding":{"type":"internet-exposed","title":"EC2 instances should not have public IP","desc":"EC2 instance has a public IP address","remediation":{"desc":"Remove public IP from EC2 instances"}}}
{"metadata":{"event_code":"rds_instance_encryption_enabled","product":{"name":"Prowler","version":"4.0.0"}},"severity":"High","status":"FAIL","resources":[{"uid":"arn:aws:rds:us-east-1:123456789012:db:mydb","type":"AwsRdsDbInstance","region":"us-east-1"}],"finding":{"type":"encryption","title":"RDS instances should be encrypted","desc":"RDS instance is not encrypted","remediation":{"desc":"Enable encryption for RDS instances"}}}`,
			expected: 2,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				assert.Len(t, findings, 2)

				// Check first finding
				assert.Equal(t, "internet-exposed", findings[0].Type)
				assert.Equal(t, "medium", findings[0].Severity)

				// Check second finding
				assert.Equal(t, "encryption", findings[1].Type)
				assert.Equal(t, "high", findings[1].Severity)
			},
		},
		{
			name: "Mixed status - only FAIL processed",
			input: `[
				{"Status": "PASS", "CheckID": "s3_bucket_versioning_enabled"},
				{"Status": "FAIL", "CheckID": "s3_bucket_public_write_prohibited", "Severity": "critical", "ResourceArn": "arn:aws:s3:::my-bucket", "CheckTitle": "S3 bucket public write", "Description": "desc", "Risk": "risk", "Region": "us-east-1", "ResourceType": "AwsS3Bucket", "Remediation": {"Recommendation": {"Text": "fix"}}},
				{"Status": "MANUAL", "CheckID": "manual_check"}
			]`,
			expected: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				assert.Len(t, findings, 1)
				assert.Contains(t, findings[0].Metadata["check_id"], "public_write")
			},
		},
		{
			name:     "Empty results",
			input:    "[]",
			expected: 0,
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

func TestProwlerScanner_ParseResults_InvalidJSON(t *testing.T) {
	scanner := NewProwlerScanner(Config{}, []string{}, []string{}, nil)

	_, err := scanner.ParseResults([]byte("invalid json"))
	assert.Error(t, err)
	assert.IsType(t, &ScannerError{}, err)
}

func TestProwlerScanner_MapCheckToType(t *testing.T) {
	scanner := NewProwlerScanner(Config{}, []string{}, []string{}, nil)

	tests := []struct {
		checkID  string
		expected string
	}{
		{"s3_bucket_encryption_enabled", "encryption"},
		{"ec2_instance_public_ip", "internet-exposed"},
		{"cloudtrail_logging_enabled", "logging"},
		{"rds_instance_backup_enabled", "resilience"},
		{"iam_user_mfa_enabled", "iam"},
		{"ssm_parameter_store_secret", "secrets"},
		{"lambda_function_url_cors", "misconfiguration"},
		{"unknown_check", "misconfiguration"},
	}

	for _, tt := range tests {
		t.Run(tt.checkID, func(t *testing.T) {
			assert.Equal(t, tt.expected, scanner.mapCheckToType(tt.checkID))
		})
	}
}

func TestNewProwlerScanner(t *testing.T) {
	// Test with no regions defaults to "all"
	scanner1 := NewProwlerScanner(Config{}, []string{"profile1"}, []string{}, nil)
	assert.Equal(t, []string{"all"}, scanner1.regions)

	// Test with specific regions
	scanner2 := NewProwlerScanner(Config{}, []string{"profile1"}, []string{"us-east-1", "eu-west-1"}, []string{"s3", "ec2"})
	assert.Equal(t, []string{"us-east-1", "eu-west-1"}, scanner2.regions)
	assert.Equal(t, []string{"s3", "ec2"}, scanner2.services)
}

func TestProwlerScanner_ParseNDJSON(t *testing.T) {
	scanner := NewProwlerScanner(Config{}, []string{}, []string{}, nil)

	// Test OCSF format
	inputOCSF := `{"metadata":{"event_code":"test1"},"status":"FAIL"}
{"metadata":{"event_code":"test2"},"status":"FAIL"}

{"metadata":{"event_code":"test3"},"status":"PASS"}
invalid line`

	resultsOCSF := scanner.parseNDJSONOCSF([]byte(inputOCSF))
	assert.Len(t, resultsOCSF, 3)
	assert.Equal(t, "test1", resultsOCSF[0].Metadata.EventCode)

	// Test Native format
	inputNative := `{"CheckID":"check1","Status":"FAIL"}
{"CheckID":"check2","Status":"FAIL"}
invalid line
{"CheckID":"check3","Status":"PASS"}`

	resultsNative := scanner.parseNDJSONNative([]byte(inputNative))
	assert.Len(t, resultsNative, 3)
	assert.Equal(t, "check1", resultsNative[0].CheckID)
}
