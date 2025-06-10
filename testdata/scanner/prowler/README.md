# Prowler Test Data

This directory contains test data for the Prowler AWS security scanner integration.

## Files

- **ocsf-output.json** - Sample Prowler output in OCSF (Open Cybersecurity Schema Framework) format used by Prowler v4+
- **native-output.json** - Sample Prowler output in native JSON format used by Prowler v3

## Test Data Overview

The test data includes common AWS security findings across multiple services:

### OCSF Format Findings:
1. **IAM MFA Not Enabled** (High) - User without MFA for console access
2. **S3 Public Read Access** (Critical) - Bucket allowing public read
3. **EC2 IMDSv2 Not Enabled** (Medium) - Instance using IMDSv1
4. **RDS Backup Disabled** (Medium) - Database without automated backups
5. **Weak Password Policy** (Low) - Missing uppercase requirement

### Native Format Findings:
1. **S3 Default Encryption** (Medium) - Bucket without encryption
2. **Root Hardware MFA** (Critical) - Root user without hardware MFA
3. **Default Security Group** (High) - Default SG with permissive rules
4. **CloudTrail Logging** (Low) - CloudTrail bucket without access logs

## Usage in Tests

```go
// Load test data
ocsfData, _ := os.ReadFile("testdata/scanner/prowler/ocsf-output.json")
nativeData, _ := os.ReadFile("testdata/scanner/prowler/native-output.json")

// Test parser
scanner := NewProwlerScanner(config, profiles, regions, services)
findings, err := scanner.ParseResults(ocsfData)
```

## Updating Test Data

To generate new test data from actual Prowler runs:

```bash
# Run specific safe checks
prowler aws \
  --checks iam_user_mfa_enabled_console_access \
  --output-formats json-ocsf \
  --output-directory ./testdata/scanner/prowler \
  --status FAIL

# Or use the generation script
./scripts/test/generate-prowler-testdata.sh
```

## Notes

- Test data uses fake AWS account ID (123456789012)
- Resource ARNs are realistic but not real
- Findings represent common security issues
- Both Prowler v3 (native) and v4 (OCSF) formats are included