#!/usr/bin/env bash
# Generate Prowler test data - requires AWS credentials or LocalStack

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/testdata/scanner/prowler"

echo "=== Generating Prowler Test Data ==="
echo "Output directory: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

# Check if we have AWS credentials
if [ -z "$AWS_ACCESS_KEY_ID" ] && [ -z "$AWS_PROFILE" ]; then
    echo "⚠️  No AWS credentials found. Generating mock data instead..."
    
    # Create mock Prowler output based on real format
    cat > "$OUTPUT_DIR/mock-prowler-output.json" << 'EOF'
{
  "metadata": {
    "scan_date": "2025-06-10T04:00:00Z",
    "prowler_version": "3.12.0",
    "account_id": "123456789012",
    "region": "us-east-1"
  },
  "findings": [
    {
      "metadata": {
        "event_code": "iam_user_mfa_enabled_console_access",
        "event_name": "IAM users with console access should have MFA enabled"
      },
      "severity": "high",
      "status": "FAIL",
      "status_extended": "User 'admin' has console access but MFA is not enabled",
      "resource_id": "arn:aws:iam::123456789012:user/admin",
      "resource_type": "iam_user",
      "region": "global",
      "compliance": {
        "cis_1.4": ["2.1.1"],
        "pci_dss_v3.2.1": ["8.3.1"],
        "nist_800_53_r5": ["IA-2(1)", "IA-2(2)"]
      }
    },
    {
      "metadata": {
        "event_code": "s3_bucket_public_access",
        "event_name": "S3 buckets should not be publicly accessible"
      },
      "severity": "critical",
      "status": "FAIL",
      "status_extended": "Bucket 'my-public-bucket' allows public read access",
      "resource_id": "arn:aws:s3:::my-public-bucket",
      "resource_type": "s3_bucket",
      "region": "us-east-1",
      "compliance": {
        "cis_1.4": ["2.1.5"],
        "pci_dss_v3.2.1": ["1.3.1", "1.3.2"]
      }
    },
    {
      "metadata": {
        "event_code": "ec2_instance_public_ip",
        "event_name": "EC2 instances should not have public IP addresses"
      },
      "severity": "medium",
      "status": "FAIL",
      "status_extended": "Instance i-1234567890abcdef0 has public IP 54.123.45.67",
      "resource_id": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
      "resource_type": "ec2_instance",
      "region": "us-east-1"
    },
    {
      "metadata": {
        "event_code": "rds_instance_backup_enabled",
        "event_name": "RDS instances should have automated backups enabled"
      },
      "severity": "medium",
      "status": "FAIL",
      "status_extended": "RDS instance 'production-db' has backup retention period set to 0",
      "resource_id": "arn:aws:rds:us-east-1:123456789012:db:production-db",
      "resource_type": "rds_instance",
      "region": "us-east-1"
    },
    {
      "metadata": {
        "event_code": "cloudtrail_enabled_all_regions",
        "event_name": "CloudTrail should be enabled in all regions"
      },
      "severity": "high",
      "status": "FAIL",
      "status_extended": "CloudTrail is not enabled in regions: eu-west-1, ap-southeast-1",
      "resource_id": "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail",
      "resource_type": "cloudtrail",
      "region": "global"
    }
  ]
}
EOF

    # Create OCSF format output (newer Prowler format)
    cat > "$OUTPUT_DIR/mock-prowler-ocsf.jsonl" << 'EOF'
{"activity_name": "IAM users with console access should have MFA enabled", "activity_id": 12, "category_name": "Findings", "category_uid": 2, "class_name": "Detection Finding", "class_uid": 2004, "cloud": {"account": {"uid": "123456789012"}, "region": "global", "provider": "aws"}, "compliance": {"requirements": ["CIS 1.4: 2.1.1", "PCI-DSS v3.2.1: 8.3.1"]}, "finding_info": {"uid": "iam_user_mfa_enabled_console_access", "title": "IAM users with console access should have MFA enabled", "desc": "User 'admin' has console access but MFA is not enabled"}, "metadata": {"event_code": "iam_user_mfa_enabled_console_access", "product": {"name": "Prowler", "version": "3.12.0", "vendor_name": "Prowler"}}, "resources": [{"uid": "arn:aws:iam::123456789012:user/admin", "type": "iam_user", "name": "admin"}], "risk_score": 80, "severity": "High", "severity_id": 3, "status": "FAIL", "status_id": 2, "time": 1718424000, "type_name": "Detection Finding: Create", "type_uid": 200401}
{"activity_name": "S3 buckets should not be publicly accessible", "activity_id": 12, "category_name": "Findings", "category_uid": 2, "class_name": "Detection Finding", "class_uid": 2004, "cloud": {"account": {"uid": "123456789012"}, "region": "us-east-1", "provider": "aws"}, "compliance": {"requirements": ["CIS 1.4: 2.1.5", "PCI-DSS v3.2.1: 1.3.1"]}, "finding_info": {"uid": "s3_bucket_public_access", "title": "S3 buckets should not be publicly accessible", "desc": "Bucket 'my-public-bucket' allows public read access"}, "metadata": {"event_code": "s3_bucket_public_access", "product": {"name": "Prowler", "version": "3.12.0", "vendor_name": "Prowler"}}, "resources": [{"uid": "arn:aws:s3:::my-public-bucket", "type": "s3_bucket", "name": "my-public-bucket"}], "risk_score": 95, "severity": "Critical", "severity_id": 4, "status": "FAIL", "status_id": 2, "time": 1718424000, "type_name": "Detection Finding: Create", "type_uid": 200401}
{"activity_name": "EC2 instances should not have public IP addresses", "activity_id": 12, "category_name": "Findings", "category_uid": 2, "class_name": "Detection Finding", "class_uid": 2004, "cloud": {"account": {"uid": "123456789012"}, "region": "us-east-1", "provider": "aws"}, "finding_info": {"uid": "ec2_instance_public_ip", "title": "EC2 instances should not have public IP addresses", "desc": "Instance i-1234567890abcdef0 has public IP 54.123.45.67"}, "metadata": {"event_code": "ec2_instance_public_ip", "product": {"name": "Prowler", "version": "3.12.0", "vendor_name": "Prowler"}}, "resources": [{"uid": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0", "type": "ec2_instance", "name": "i-1234567890abcdef0"}], "risk_score": 60, "severity": "Medium", "severity_id": 2, "status": "FAIL", "status_id": 2, "time": 1718424000, "type_name": "Detection Finding: Create", "type_uid": 200401}
EOF

    echo "Created mock Prowler output files for parser testing"
    
    # Create LocalStack setup script
    cat > "$OUTPUT_DIR/setup-localstack.sh" << 'EOF'
#!/bin/bash
# Setup LocalStack for Prowler testing (experimental)

echo "Starting LocalStack..."
docker run -d \
  --name localstack-prowler \
  -p 4566:4566 \
  -e SERVICES=iam,s3,ec2,rds,cloudtrail \
  -e DEFAULT_REGION=us-east-1 \
  localstack/localstack

echo "Waiting for LocalStack to be ready..."
sleep 10

# Configure AWS CLI for LocalStack
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566

echo "Creating test resources..."
# Create S3 bucket
aws s3 mb s3://test-bucket

# Create IAM user
aws iam create-user --user-name test-user

echo "LocalStack setup complete!"
echo "To run Prowler against LocalStack:"
echo "prowler aws --endpoint-url http://localhost:4566"
EOF
    chmod +x "$OUTPUT_DIR/setup-localstack.sh"

else
    echo "AWS credentials found. Running limited Prowler scan..."
    
    # Run Prowler with specific fast checks only
    echo "Running Prowler with minimal checks..."
    
    # Check if prowler is installed
    if ! command -v prowler &> /dev/null; then
        echo "❌ Prowler is not installed. Please install it first:"
        echo "   pip install prowler"
        exit 1
    fi
    
    # Run specific quick checks that don't cost money
    prowler aws \
        --checks iam_user_mfa_enabled_console_access \
        --output-formats json \
        --output-directory "$OUTPUT_DIR" \
        --no-banner \
        2>/dev/null || true
    
    # Also try OCSF format
    prowler aws \
        --checks iam_user_mfa_enabled_console_access \
        --output-formats ocsf \
        --output-directory "$OUTPUT_DIR" \
        --no-banner \
        2>/dev/null || true
        
    echo "Limited Prowler scan complete"
fi

# Create integration test helper
cat > "$OUTPUT_DIR/prowler-test-helper.go" << 'EOF'
package prowler_test

import (
    "encoding/json"
    "strings"
)

// MockProwlerOutput generates mock Prowler output for testing
func MockProwlerOutput() string {
    return `{
        "metadata": {
            "event_code": "test_check",
            "event_name": "Test Security Check"
        },
        "severity": "high",
        "status": "FAIL",
        "status_extended": "Test finding for integration testing",
        "resource_id": "arn:aws:test::123456789012:resource/test",
        "resource_type": "test_resource",
        "region": "us-east-1"
    }`
}

// MockProwlerOCSFOutput generates mock OCSF format output
func MockProwlerOCSFOutput() string {
    return `{"activity_name": "Test Security Check", "class_uid": 2004, "metadata": {"event_code": "test_check"}, "status": "FAIL"}`
}
EOF

# Create summary
cat > "$OUTPUT_DIR/README.md" << 'EOF'
# Prowler Test Data

Generated on: $(date)

## Overview

Prowler requires AWS credentials to run actual scans. This directory contains:
1. Mock data for parser testing (no AWS required)
2. Scripts for LocalStack setup (experimental)
3. Helper functions for integration tests

## Files

### Mock Data (No AWS Required)
- **mock-prowler-output.json** - Sample Prowler findings in JSON format
- **mock-prowler-ocsf.jsonl** - Sample findings in OCSF format (newer Prowler)

### For Real Testing
- **setup-localstack.sh** - Script to setup LocalStack for local AWS simulation
- **prowler-test-helper.go** - Go helper functions for tests

## Testing Approaches

### 1. Parser Testing (Recommended)
Use the mock data files to test the Prowler parser without AWS:
```go
func TestProwlerParser(t *testing.T) {
    data, _ := ioutil.ReadFile("testdata/scanner/prowler/mock-prowler-output.json")
    findings, err := parser.ParseResults(data)
    // Test parsing logic
}
```

### 2. LocalStack Testing (Experimental)
```bash
# Start LocalStack
./setup-localstack.sh

# Run Prowler against LocalStack
prowler aws --endpoint-url http://localhost:4566

# Stop LocalStack
docker stop localstack-prowler
docker rm localstack-prowler
```

### 3. Real AWS Testing (Requires Credentials)
```bash
# Run specific safe checks
prowler aws --checks iam_user_mfa_enabled_console_access

# Run checks for specific service
prowler aws --services iam --severity high
```

## Common Prowler Findings

1. **IAM Issues**
   - MFA not enabled for console users
   - Root account usage
   - Access keys not rotated
   - Excessive permissions

2. **S3 Issues**
   - Public bucket access
   - Missing encryption
   - No versioning enabled
   - Missing access logging

3. **EC2 Issues**
   - Public IP addresses
   - Default security groups
   - Unencrypted EBS volumes
   - Missing IMDSv2

4. **RDS Issues**
   - No automated backups
   - Public accessibility
   - Default master username
   - Unencrypted storage

## Integration Test Strategy

Since Prowler requires AWS access, the recommended approach is:

1. **Use mock data for CI/CD** - Fast and reliable
2. **Use LocalStack for development** - Good for testing scanner integration
3. **Use real AWS for periodic validation** - Run weekly/monthly with limited checks
EOF

echo -e "\n✅ Prowler test data setup complete!"
echo "📁 Output directory: $OUTPUT_DIR"
echo "📝 See $OUTPUT_DIR/README.md for testing approaches"