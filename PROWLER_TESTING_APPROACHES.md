# Prowler AWS Security Scanner Testing Approaches

## Overview

Testing Prowler presents unique challenges since it requires AWS credentials and access to AWS services. This document analyzes different approaches for testing the Prowler scanner integration in the Prismatic project.

## Testing Approaches Comparison

### 1. Parser-Only Testing (Current Implementation) ✅

**What it is**: Test only the parsing logic using mock JSON data without running Prowler.

**Implementation**:
```go
func TestProwlerScanner_ParseResults(t *testing.T) {
    scanner := NewProwlerScanner(Config{}, []string{"default"}, []string{"us-east-1"}, nil)
    
    // Test with mock JSON data
    mockJSON := `[{"metadata": {...}, "status": "FAIL", ...}]`
    findings, err := scanner.ParseResults([]byte(mockJSON))
    // Assert parsing logic
}
```

**Pros**:
- Fast execution (< 1 second)
- No external dependencies
- Works in CI/CD pipelines
- No AWS costs
- Deterministic results
- Easy to maintain

**Cons**:
- Doesn't test actual Prowler execution
- Doesn't verify command-line arguments
- May miss integration issues
- Mock data can become outdated

**Best for**: Unit tests, CI/CD pipelines, rapid development

### 2. LocalStack Integration Testing 🚧

**What it is**: Run Prowler against LocalStack, which simulates AWS services locally.

**Implementation**:
```go
func TestProwlerScanner_LocalStackIntegration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping LocalStack integration test")
    }
    
    // Start LocalStack container
    ctx := context.Background()
    localstack, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
        ContainerRequest: testcontainers.ContainerRequest{
            Image:        "localstack/localstack:latest",
            ExposedPorts: []string{"4566/tcp"},
            Env: map[string]string{
                "SERVICES": "iam,s3,ec2,cloudtrail",
            },
        },
    })
    
    // Configure AWS CLI for LocalStack
    os.Setenv("AWS_ENDPOINT_URL", "http://localhost:4566")
    os.Setenv("AWS_ACCESS_KEY_ID", "test")
    os.Setenv("AWS_SECRET_ACCESS_KEY", "test")
    
    // Create test resources
    // ... create S3 buckets, IAM users, etc.
    
    // Run Prowler
    scanner := NewProwlerScanner(config, []string{"default"}, []string{"us-east-1"}, nil)
    result, err := scanner.Scan(ctx)
}
```

**Pros**:
- Tests actual Prowler execution
- No AWS costs
- Can test scanner integration
- Isolated environment
- Reproducible results

**Cons**:
- Limited AWS service coverage in LocalStack
- Prowler may not fully support LocalStack endpoints
- Requires Docker
- Slower than unit tests (30-60 seconds)
- LocalStack behavior may differ from real AWS
- Complex setup

**Best for**: Integration testing in development, testing scanner logic

### 3. Mock AWS Credentials with Skip Testing 🔄

**What it is**: Test Prowler execution but skip if no AWS credentials are available.

**Implementation**:
```go
func TestProwlerScanner_MockAWSIntegration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping AWS integration test")
    }
    
    // Check for AWS credentials
    if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
        t.Skip("AWS credentials not available")
    }
    
    // Use test-specific AWS profile/region
    scanner := NewProwlerScanner(config, 
        []string{"prowler-test"}, 
        []string{"us-east-1"}, 
        []string{"iam"}) // Limited services
    
    // Run with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    result, err := scanner.Scan(ctx)
}
```

**Pros**:
- Tests real Prowler behavior
- Can run in CI with test AWS account
- Validates command execution
- Can test specific, low-impact checks

**Cons**:
- Requires AWS credentials
- Potential AWS costs
- Not suitable for all environments
- Results may vary based on AWS state

**Best for**: Periodic validation, pre-release testing

### 4. Test Data Generation Approach 📁

**What it is**: Generate test data files using limited Prowler runs.

**Implementation**:
```bash
#!/bin/bash
# Run limited Prowler checks to generate test data
prowler aws \
    --checks iam_user_mfa_enabled_console_access \
    --output-formats json,ocsf \
    --output-directory testdata/scanner/prowler \
    --status FAIL
```

**Pros**:
- Real Prowler output format
- Can update test data periodically
- Good for parser testing
- Minimal AWS impact

**Cons**:
- Test data can become stale
- Requires manual updates
- Initial generation needs AWS access

**Best for**: Creating realistic test fixtures

### 5. Mocked Command Execution 🎭

**What it is**: Mock the Prowler binary execution entirely.

**Implementation**:
```go
func TestProwlerScanner_MockedExecution(t *testing.T) {
    // Create mock prowler script
    mockScript := `#!/bin/bash
    echo '[{"status": "FAIL", "severity": "high", ...}]'
    exit 3  # Prowler exit code when findings exist
    `
    
    // Override PATH to use mock
    oldPath := os.Getenv("PATH")
    defer os.Setenv("PATH", oldPath)
    os.Setenv("PATH", mockDir + ":" + oldPath)
    
    scanner := NewProwlerScanner(config, []string{"default"}, nil, nil)
    result, err := scanner.Scan(context.Background())
}
```

**Pros**:
- Full control over output
- Fast execution
- No external dependencies
- Can test error scenarios

**Cons**:
- Doesn't test real Prowler
- Complex to maintain
- May mask integration issues

**Best for**: Testing error handling, command execution logic

## Recommended Testing Strategy

### 1. **Primary: Parser-Only Testing** (Unit Tests)
- Use for all CI/CD pipelines
- Maintain comprehensive mock data sets
- Test all output formats (native, OCSF, NDJSON)
- Cover edge cases and error scenarios

### 2. **Secondary: Test Data Generation** (Integration Fixtures)
- Generate monthly or on-demand
- Use minimal, safe checks (e.g., IAM MFA status)
- Store in version control
- Document generation process

### 3. **Optional: LocalStack Integration** (Development Testing)
- Use for local development
- Test scanner integration logic
- Validate command construction
- Not required for CI/CD

### 4. **Periodic: Real AWS Testing** (Validation)
- Run weekly/monthly in test account
- Use restricted IAM role
- Focus on read-only checks
- Validate parser against real output

## Implementation Plan

### Phase 1: Enhance Current Parser Tests ✅
```go
// Add more comprehensive test cases
- OCSF format variations
- NDJSON parsing
- Large result sets
- Malformed JSON handling
- Empty results
- Mixed status checks
```

### Phase 2: Create Test Data Generator
```bash
# Script to generate minimal test data
./scripts/test/generate-prowler-testdata.sh
```

### Phase 3: Add LocalStack Integration (Optional)
```go
// Create integration test with LocalStack
// Tag with build constraint: //go:build integration && localstack
```

### Phase 4: Document Testing Approach
```markdown
# Add to internal/scanner/README.md
- Testing philosophy
- How to update test data
- Running integration tests
```

## Security Considerations

1. **Never commit real AWS credentials**
2. **Use read-only IAM roles for testing**
3. **Sanitize test data for sensitive information**
4. **Run tests in isolated AWS accounts**
5. **Limit Prowler checks to non-intrusive ones**

## Cost Considerations

1. **Parser tests**: $0
2. **LocalStack**: $0 (open source version)
3. **Test data generation**: ~$0.01 per run (minimal API calls)
4. **Full AWS testing**: Variable, use cost controls

## Conclusion

The current parser-only testing approach is the most practical for continuous testing. It provides good coverage of the parsing logic without external dependencies or costs. Supplementing this with periodic test data generation ensures the mock data remains current.

LocalStack integration could be valuable for development but isn't critical given Prowler's limited endpoint configuration options. Real AWS testing should be reserved for validation in controlled environments.