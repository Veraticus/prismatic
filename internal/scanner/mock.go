package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
)

// MockScanner generates realistic fake findings for testing.
type MockScanner struct {
	*BaseScanner
	scannerType string
}

// NewMockScanner creates a mock scanner that mimics a real scanner.
func NewMockScanner(scannerType string, config Config) *MockScanner {
	return &MockScanner{
		BaseScanner: NewBaseScanner("mock-"+scannerType, config),
		scannerType: scannerType,
	}
}

// Scan generates mock findings based on scanner type.
func (m *MockScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
	startTime := time.Now()

	// Simulate some scanning time
	select {
	case <-time.After(time.Duration(rand.Intn(3)+1) * time.Second): //nolint:gosec // Weak random is acceptable for mock delays
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Generate findings based on scanner type
	var findings []models.Finding

	switch m.scannerType {
	case "prowler":
		findings = m.generateAWSFindings()
	case "trivy":
		findings = m.generateContainerFindings()
	case "kubescape":
		findings = m.generateKubernetesFindings()
	case "nuclei":
		findings = m.generateWebFindings()
	case "gitleaks":
		findings = m.generateSecretsFindings()
	case "checkov":
		findings = m.generateIaCFindings()
	default:
		findings = m.generateGenericFindings()
	}

	// Mock raw output
	rawOutput, _ := json.MarshalIndent(findings, "", "  ")

	return &models.ScanResult{
		Scanner:   m.Name(),
		Version:   "mock-1.0.0",
		StartTime: startTime,
		EndTime:   time.Now(),
		RawOutput: rawOutput,
		Findings:  findings,
	}, nil
}

// ParseResults is not needed for mock scanner as we generate normalized findings directly.
func (m *MockScanner) ParseResults(raw []byte) ([]models.Finding, error) {
	var findings []models.Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return nil, fmt.Errorf("parsing mock results: %w", err)
	}
	return findings, nil
}

func (m *MockScanner) generateAWSFindings() []models.Finding {
	findings := []models.Finding{
		*models.NewFinding("prowler", "iam_root_no_mfa", "arn:aws:iam::123456789012:root", ""),
		*models.NewFinding("prowler", "s3_bucket_public_read", "arn:aws:s3:::my-public-bucket", ""),
		*models.NewFinding("prowler", "ec2_security_group_ssh_open", "sg-0123456789abcdef0", "us-east-1"),
		*models.NewFinding("prowler", "rds_instance_no_encryption", "arn:aws:rds:us-east-1:123456789012:db:prod-db", ""),
		*models.NewFinding("prowler", "cloudtrail_not_enabled", "arn:aws:cloudtrail:us-east-1:123456789012:trail/management", ""),
	}

	// Fill in details
	findings[0].Severity = "critical"
	findings[0].Title = "Root account does not have MFA enabled"
	findings[0].Description = "The AWS root account does not have multi-factor authentication enabled, which significantly increases security risk."
	findings[0].Remediation = "Enable MFA for the root account immediately"
	findings[0].Impact = "Unauthorized access to root account could lead to complete AWS account compromise"
	findings[0].References = []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa"}

	findings[1].Severity = "high"
	findings[1].Title = "S3 bucket allows public read access"
	findings[1].Description = "The S3 bucket 'my-public-bucket' is configured to allow public read access, potentially exposing sensitive data."
	findings[1].Remediation = "Review bucket policy and remove public access unless explicitly required"
	findings[1].Impact = "Sensitive data could be exposed to unauthorized parties"

	findings[2].Severity = "high"
	findings[2].Title = "Security group allows SSH from anywhere"
	findings[2].Description = "Security group sg-0123456789abcdef0 allows SSH (port 22) access from 0.0.0.0/0"
	findings[2].Remediation = "Restrict SSH access to specific IP ranges"
	findings[2].Impact = "Instances could be accessed by unauthorized users"

	findings[3].Severity = "medium"
	findings[3].Title = "RDS instance not encrypted"
	findings[3].Description = "RDS instance 'prod-db' does not have encryption at rest enabled"
	findings[3].Remediation = "Enable encryption for the RDS instance"
	findings[3].Impact = "Database contents could be exposed if storage is compromised"

	findings[4].Severity = "medium"
	findings[4].Title = "CloudTrail is not enabled"
	findings[4].Description = "CloudTrail logging is not enabled for management events"
	findings[4].Remediation = "Enable CloudTrail for all regions"
	findings[4].Impact = "Security incidents and API calls cannot be audited"

	return findings
}

func (m *MockScanner) generateContainerFindings() []models.Finding {
	findings := []models.Finding{
		*models.NewFinding("trivy", "CVE-2023-12345", "nginx:latest", "libssl1.1"),
		*models.NewFinding("trivy", "CVE-2023-23456", "nginx:latest", "libc6"),
		*models.NewFinding("trivy", "CVE-2022-34567", "alpine:latest", "busybox"),
		*models.NewFinding("trivy", "GHSA-1234-5678-9abc", "node:16", "npm"),
	}

	findings[0].Severity = "critical"
	findings[0].Title = "OpenSSL vulnerability allows remote code execution"
	findings[0].Description = "A buffer overflow in OpenSSL 1.1.1 allows attackers to execute arbitrary code"
	findings[0].Remediation = "Update libssl1.1 to version 1.1.1t or later"
	findings[0].Impact = "Remote code execution on container"
	findings[0].References = []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-12345"}

	findings[1].Severity = "high"
	findings[1].Title = "glibc buffer overflow vulnerability"
	findings[1].Description = "Buffer overflow in glibc DNS resolver"
	findings[1].Remediation = "Update libc6 to version 2.35-r1 or later"
	findings[1].Impact = "Potential remote code execution"

	findings[2].Severity = "medium"
	findings[2].Title = "BusyBox shell injection vulnerability"
	findings[2].Description = "Shell injection possible through crafted input"
	findings[2].Remediation = "Update busybox to version 1.35.0-r2 or later"
	findings[2].Impact = "Local privilege escalation"

	findings[3].Severity = "low"
	findings[3].Title = "npm prototype pollution vulnerability"
	findings[3].Description = "Prototype pollution in npm package handling"
	findings[3].Remediation = "Update npm to version 8.19.4 or later"
	findings[3].Impact = "Application behavior modification"

	return findings
}

func (m *MockScanner) generateKubernetesFindings() []models.Finding {
	findings := []models.Finding{
		*models.NewFinding("kubescape", "C-0034", "default/web-deployment", ""),
		*models.NewFinding("kubescape", "C-0035", "kube-system/admin-binding", ""),
		*models.NewFinding("kubescape", "C-0061", "default/api-service", ""),
	}

	findings[0].Severity = "high"
	findings[0].Title = "Automatic mapping of service account"
	findings[0].Description = "Pod does not disable automatic mounting of service account token"
	findings[0].Remediation = "Set automountServiceAccountToken to false in pod spec"
	findings[0].Impact = "Pods have unnecessary access to Kubernetes API"
	findings[0].Framework = "NSA-CISA"

	findings[1].Severity = "critical"
	findings[1].Title = "Cluster-admin binding found"
	findings[1].Description = "ClusterRoleBinding grants cluster-admin privileges"
	findings[1].Remediation = "Review and restrict cluster-admin bindings"
	findings[1].Impact = "Excessive privileges could lead to cluster compromise"
	findings[1].Framework = "CIS"

	findings[2].Severity = "medium"
	findings[2].Title = "Container running as root"
	findings[2].Description = "Container in pod api-service runs with root privileges"
	findings[2].Remediation = "Use runAsNonRoot and specify a user ID"
	findings[2].Impact = "Container escape could lead to host compromise"
	findings[2].Framework = "PCI-DSS"

	return findings
}

func (m *MockScanner) generateWebFindings() []models.Finding {
	findings := []models.Finding{
		*models.NewFinding("nuclei", "exposed-panels/gitlab-detect", "https://gitlab.example.com", "/users/sign_in"),
		*models.NewFinding("nuclei", "technologies/nginx-version", "https://www.example.com", "/"),
		*models.NewFinding("nuclei", "cves/2021/CVE-2021-41773", "https://api.example.com", "/cgi-bin/"),
	}

	findings[0].Severity = "info"
	findings[0].Title = "GitLab login panel detected"
	findings[0].Description = "GitLab instance login panel is exposed"
	findings[0].Remediation = "Ensure GitLab instance is properly secured and up to date"
	findings[0].Impact = "Information disclosure about infrastructure"

	findings[1].Severity = "low"
	findings[1].Title = "Nginx version disclosed"
	findings[1].Description = "Server header discloses Nginx version 1.18.0"
	findings[1].Remediation = "Configure server_tokens off in nginx.conf"
	findings[1].Impact = "Version disclosure aids attackers in targeting known vulnerabilities"

	findings[2].Severity = "critical"
	findings[2].Title = "Apache Path Traversal vulnerability"
	findings[2].Description = "Apache 2.4.49 path traversal and RCE vulnerability detected"
	findings[2].Remediation = "Update Apache to version 2.4.51 or later immediately"
	findings[2].Impact = "Remote code execution on web server"
	findings[2].References = []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"}

	return findings
}

func (m *MockScanner) generateSecretsFindings() []models.Finding {
	// Usually no findings in a clean scan
	findings := []models.Finding{}

	// Occasionally add a finding
	if rand.Float32() < 0.3 { //nolint:gosec // Weak random is acceptable for mock data
		finding := models.NewFinding("gitleaks", "generic-api-key", "src/config/config.js", "line 42")
		finding.Severity = "high"
		finding.Title = "Potential API key found in source code"
		finding.Description = "Detected pattern matching generic API key format"
		finding.Remediation = "Remove hardcoded secrets and use environment variables or secret management service"
		finding.Impact = "Exposed credentials could lead to unauthorized access"
		findings = append(findings, *finding)
	}

	return findings
}

func (m *MockScanner) generateIaCFindings() []models.Finding {
	findings := []models.Finding{
		*models.NewFinding("checkov", "CKV_AWS_23", "terraform/s3.tf", "line 15-22"),
		*models.NewFinding("checkov", "CKV_AWS_79", "terraform/rds.tf", "line 8"),
		*models.NewFinding("checkov", "CKV2_AWS_6", "terraform/network.tf", "line 45"),
	}

	findings[0].Severity = "medium"
	findings[0].Title = "S3 bucket versioning not enabled"
	findings[0].Description = "S3 bucket does not have versioning enabled"
	findings[0].Remediation = "Enable versioning on S3 bucket"
	findings[0].Impact = "Cannot recover from accidental deletions or modifications"

	findings[1].Severity = "medium"
	findings[1].Title = "RDS instance does not have deletion protection"
	findings[1].Description = "RDS instance can be accidentally deleted"
	findings[1].Remediation = "Enable deletion protection for production databases"
	findings[1].Impact = "Database could be accidentally deleted"

	findings[2].Severity = "low"
	findings[2].Title = "VPC Flow Logs not enabled"
	findings[2].Description = "VPC does not have flow logs enabled for network monitoring"
	findings[2].Remediation = "Enable VPC Flow Logs"
	findings[2].Impact = "Cannot monitor network traffic for security analysis"

	return findings
}

func (m *MockScanner) generateGenericFindings() []models.Finding {
	severities := []string{"critical", "high", "medium", "low", "info"}
	findings := make([]models.Finding, rand.Intn(5)+3) //nolint:gosec // Weak random is acceptable for mock data

	for i := range findings {
		finding := models.NewFinding(
			m.scannerType,
			fmt.Sprintf("FINDING-%d", i+1),
			fmt.Sprintf("resource-%d", i+1),
			"",
		)
		finding.Severity = severities[rand.Intn(len(severities))] //nolint:gosec // Weak random is acceptable for mock data
		finding.Title = fmt.Sprintf("Mock finding %d from %s", i+1, m.scannerType)
		finding.Description = "This is a mock finding for testing purposes"
		finding.Remediation = "No action needed - this is a mock finding"
		finding.Impact = "No impact - mock finding only"
		findings[i] = *finding
	}

	return findings
}
