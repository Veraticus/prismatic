# Fast Integration Testing for Security Scanners

This document describes how to run fast integration tests for Nuclei and Checkov that execute in under 5 seconds while still testing real scanner functionality.

## Running Integration Tests

```bash
# Run all integration tests (requires -tags integration)
go test -tags integration ./internal/scanner -run Integration

# Run with verbose output
go test -tags integration -v ./internal/scanner -run Integration

# Run specific scanner tests
go test -tags integration -v ./internal/scanner -run TestNucleiIntegrationFast
go test -tags integration -v ./internal/scanner -run TestCheckovIntegrationFast
```

## Nuclei Fast Execution Strategies

### 1. Minimal Template Selection

Instead of running all templates, use specific tags or template paths:

```bash
# CVE scanning only (critical and high severity)
nuclei -tags cve -severity critical,high -rl 100 -c 25 -l targets.txt

# Specific vulnerability types
nuclei -tags sqli,xss,rce -severity medium,high,critical -rl 50 -timeout 10 -l targets.txt

# Technology detection only (very fast)
nuclei -tags tech -rl 100 -c 50 -l targets.txt

# Exposed panels and admin interfaces
nuclei -tags panel -severity info,low,medium -rl 75 -l targets.txt

# Single specific template
nuclei -t cves/2021/CVE-2021-44228.yaml -rl 50 -l targets.txt
```

### 2. Performance Optimization Flags

Key flags for fast execution:

- `-rl, -rate-limit`: Set to 50-100 for local testing (default: 150)
- `-c, -concurrency`: Set to 25-50 for fast parallel execution (default: 25)
- `-timeout`: Reduce to 5-10 seconds for quick scans (default: 5)
- `-duc`: Disable update check to save startup time
- `-nc`: No color output (reduces processing)
- `-silent`: Silent mode to reduce output overhead
- `-stats`: Show statistics to monitor progress

### 3. Local Test Server

For integration testing, we use a minimal HTTP server with known vulnerabilities:

```go
// Test endpoints:
- /xss?name=test    - XSS vulnerability
- /info             - Information disclosure
- /admin            - Exposed admin panel
- /.env             - Sensitive file exposure
```

### 4. Example Integration Test Command

```go
args := []string{
    "-j",                           // JSON output
    "-tags", "xss,exposure,panel",  // Only specific tags
    "-severity", "low,medium,high", // Skip info severity  
    "-timeout", "5",                // Short timeout
    "-rate-limit", "50",            // Higher rate for local
    "-duc",                         // Disable update check
    "-nc",                          // No color
    "-silent",                      // Silent mode
}
```

## Checkov Fast Execution Strategies

### 1. Framework-Specific Scanning

Limit scanning to specific IaC frameworks:

```bash
# Terraform only
checkov -d . --framework terraform --output json --quiet

# Dockerfile only
checkov -d . --framework dockerfile --output json --quiet

# Kubernetes only
checkov -d . --framework kubernetes --output json --quiet
```

### 2. Severity and Check Filtering

```bash
# High severity only
checkov -d . --framework terraform --check HIGH --output json --quiet

# Specific check IDs
checkov -d . --check CKV_AWS_23,CKV_AWS_18,CKV_AWS_21 --output json --compact

# Skip low severity
checkov -d . --skip-check LOW --framework terraform --output json

# Encryption checks only
checkov -d . --check CKV_AWS_18,CKV_AWS_19,CKV_AWS_21 --output json
```

### 3. Performance Optimization

Key flags for fast execution:

- `--framework`: Specify single framework to avoid scanning all types
- `--check`: Run only specific check IDs
- `--skip-check`: Skip severity levels or specific checks
- `--quiet`: Reduce output verbosity
- `--compact`: Compact JSON output
- `--output json`: JSON output is faster to parse than CLI format

### 4. Minimal Test Files

For integration testing, use small IaC files with known issues:

```hcl
# vulnerable.tf - S3 without encryption, open security group
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}

resource "aws_security_group" "test" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

### 5. Example Integration Test Command

```go
args := []string{
    "--directory", absPath,
    "--output", "json",
    "--quiet",
    "--compact", 
    "--framework", "terraform",          // Only Terraform
    "--check", "CKV_AWS_18,CKV_AWS_24", // Specific checks
    "--skip-check", "LOW",              // Skip low severity
}
```

## Performance Benchmarks

Target execution times for integration tests:

- **Nuclei**: 2-4 seconds with minimal templates and local test server
- **Checkov**: 1-3 seconds with specific checks on small test files

## Best Practices

1. **Use Local Test Targets**: Avoid scanning external sites in tests
2. **Limit Template/Check Scope**: Only run what's necessary to verify functionality
3. **Parallel Execution**: Use appropriate concurrency settings for your hardware
4. **Timeout Early**: Set aggressive timeouts for integration tests
5. **Skip Updates**: Disable template/signature updates during tests
6. **Cache Results**: Reuse test fixtures and avoid repeated downloads

## Troubleshooting

If tests are running slowly:

1. Check if scanners are trying to update templates/signatures
2. Verify network connectivity isn't causing delays
3. Reduce concurrency if system is resource-constrained
4. Use more specific template/check selections
5. Enable debug logging to identify bottlenecks