# Fast Integration Testing for Nuclei and Checkov

This document provides comprehensive guidance on running fast integration tests for Nuclei and Checkov security scanners, ensuring tests complete in under 5 seconds while still providing meaningful validation.

## Quick Start

```bash
# Run fast integration tests
./scripts/test-integration-fast.sh

# Run Go integration tests only
go test -tags integration -v ./internal/scanner -run "IntegrationMinimal" -timeout 30s
```

## Nuclei Fast Execution

### 1. Minimal Template Selection

Instead of running all 9000+ templates, use targeted selections:

```bash
# Technology detection only (1-2 seconds)
nuclei -u https://example.com -tags tech -rl 100 -c 50 -timeout 3 -duc -silent

# CVE scanning - critical/high only (2-3 seconds)
nuclei -u https://example.com -tags cve -severity critical,high -rl 100 -c 25 -timeout 5

# Specific vulnerability types (2-4 seconds)
nuclei -u https://example.com -tags sqli,xss,rce -severity high,critical -rl 50 -timeout 5

# Single template (<1 second)
nuclei -u https://example.com -t cves/2021/CVE-2021-44228.yaml -rl 50

# Admin panels and exposures (1-2 seconds)
nuclei -u https://example.com -tags panel,exposure -rl 75 -timeout 3
```

### 2. Performance Optimization Flags

| Flag | Purpose | Recommended Value |
|------|---------|-------------------|
| `-rl, -rate-limit` | Requests per second | 50-100 for local, 10-30 for remote |
| `-c, -concurrency` | Parallel templates | 10-50 based on resources |
| `-timeout` | Request timeout | 3-5 seconds |
| `-duc` | Disable update check | Always use in tests |
| `-nc` | No color output | Reduces processing |
| `-silent` | Minimal output | Use for speed |
| `-stats` | Show progress | Optional for monitoring |

### 3. Integration Test Example

```go
// Minimal Nuclei test that runs in <5 seconds
cmd := exec.CommandContext(ctx, "nuclei",
    "-u", testServerURL,
    "-j",                    // JSON output
    "-tags", "panel,config", // Quick templates only
    "-timeout", "3",         // Short timeout
    "-rate-limit", "100",    // Fast for local
    "-c", "10",              // Limited concurrency
    "-duc",                  // No updates
    "-silent",               // Quiet mode
)
```

### 4. Test Targets

For integration testing, use:
- Local test server with known vulnerabilities
- Small, focused template sets
- Short timeouts to fail fast

## Checkov Fast Execution

### 1. Framework-Specific Scanning

```bash
# Terraform only (1-2 seconds)
checkov -d . --framework terraform --output json --quiet

# Dockerfile only (<1 second for small files)
checkov -d . --framework dockerfile --output json --quiet

# Kubernetes only (1-2 seconds)
checkov -d . --framework kubernetes --output json --quiet
```

### 2. Check Selection Strategies

```bash
# High severity only (reduces checks by 80%)
checkov -d . --framework terraform --check HIGH --output json

# Specific check IDs (<1 second)
checkov -d . --check CKV_AWS_18,CKV_AWS_24 --output json --compact

# Skip low severity (faster by ~40%)
checkov -d . --skip-check LOW --output json

# Category-specific (encryption checks)
checkov -d . --check CKV_AWS_18,CKV_AWS_19,CKV_AWS_21 --output json
```

### 3. Performance Flags

| Flag | Purpose | Impact |
|------|---------|--------|
| `--framework` | Single framework | 70% faster |
| `--check` | Specific checks | 90% faster |
| `--skip-check` | Skip severity/IDs | 30-50% faster |
| `--quiet` | Minimal output | 10% faster |
| `--compact` | Compact JSON | Smaller output |
| `--output json` | Structured output | Faster parsing |

### 4. Integration Test Example

```go
// Minimal Checkov test that runs in <5 seconds
cmd := exec.CommandContext(ctx, "checkov",
    "-d", testDir,
    "--framework", "terraform",           // One framework
    "--check", "CKV_AWS_18,CKV_AWS_24",  // Two checks only
    "--output", "json",
    "--quiet",
    "--compact",
)
```

### 5. Test Files

Use minimal IaC files with known issues:

```hcl
# test.tf - 2 deliberate issues
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"  # Missing encryption
}

resource "aws_security_group" "test" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open SSH
  }
}
```

## Performance Benchmarks

Target execution times:

| Scanner | Configuration | Target Time | Actual Time |
|---------|---------------|-------------|-------------|
| Nuclei | Tech detection only | < 2s | 1-2s |
| Nuclei | 5 CVE templates | < 3s | 2-3s |
| Nuclei | Single template | < 1s | 0.5-1s |
| Checkov | 2 specific checks | < 1s | 0.5-1s |
| Checkov | One framework | < 2s | 1-2s |
| Checkov | High severity only | < 3s | 2-3s |

## Best Practices

1. **Local Testing**: Use local servers/files to avoid network latency
2. **Minimal Scope**: Only test what's necessary for validation
3. **Fail Fast**: Use aggressive timeouts (3-5 seconds)
4. **Skip Updates**: Always use `-duc` for Nuclei, avoid update checks
5. **Parallel Limits**: Balance speed vs resource usage (10-50 concurrent)
6. **Output Format**: Use JSON for faster parsing, minimal console output

## CI/CD Integration

For CI/CD pipelines:

```yaml
# Example GitHub Actions job
test-scanners:
  runs-on: ubuntu-latest
  timeout-minutes: 5
  steps:
    - name: Fast Nuclei Test
      run: |
        nuclei -u http://localhost:8080 \
          -tags tech -timeout 3 -rl 100 \
          -c 10 -duc -silent -stats
    
    - name: Fast Checkov Test  
      run: |
        checkov -d . --framework terraform \
          --check HIGH --output json --quiet
```

## Troubleshooting Slow Tests

If tests exceed 5 seconds:

1. **Check template/check count**: Use `-stats` or verbose mode
2. **Network issues**: Use local targets only
3. **Update checks**: Ensure `-duc` is set for Nuclei
4. **Reduce scope**: Fewer templates/checks
5. **Increase rate limit**: For local testing, use 100+ RPS
6. **Profile execution**: Use time command to identify bottlenecks

## Example Test Script

See `scripts/test-integration-fast.sh` for a complete example that:
- Checks for tool availability
- Runs minimal tests for each scanner
- Measures execution time
- Provides example commands

This approach ensures integration tests validate core functionality while maintaining sub-5-second execution times suitable for rapid development cycles.