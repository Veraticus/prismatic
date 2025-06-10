#!/bin/bash

# Script to run fast scanner integration tests
set -e

echo "=== Running Fast Scanner Integration Tests ==="

# Check if required tools are installed
check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo "⚠️  $1 is not installed. Skipping $1 tests."
        return 1
    fi
    echo "✓ $1 is installed"
    return 0
}

echo "Checking required tools..."
HAVE_NUCLEI=$(check_tool nuclei && echo 1 || echo 0)
HAVE_CHECKOV=$(check_tool checkov && echo 1 || echo 0)
HAVE_TRIVY=$(check_tool trivy && echo 1 || echo 0)
HAVE_GITLEAKS=$(check_tool gitleaks && echo 1 || echo 0)

if [ "$HAVE_NUCLEI" = "0" ] && [ "$HAVE_CHECKOV" = "0" ] && [ "$HAVE_TRIVY" = "0" ] && [ "$HAVE_GITLEAKS" = "0" ]; then
    echo "❌ No security scanners installed. Please install at least one scanner."
    exit 1
fi

echo ""
echo "Running integration tests..."

# Run fast integration tests with timeout
go test -v -tags=integration -timeout=2m \
    ./internal/scanner \
    -run "Test.*Scanner.*Fast.*Integration|Test.*Scanner.*RealOutput|Test.*Scanner.*ParseReal.*" \
    2>&1 | grep -E "(RUN|PASS|FAIL|SKIP|Found:|Parser:|Panel:|Exposure:|---)" || true

echo ""
echo "=== Fast Integration Test Summary ==="

# Count results
TOTAL=$(go test -tags=integration -timeout=2m ./internal/scanner -run "Test.*Fast.*|Test.*Real.*" -json 2>/dev/null | jq -r 'select(.Action=="pass" or .Action=="fail" or .Action=="skip") | .Action' | wc -l || echo 0)
PASSED=$(go test -tags=integration -timeout=2m ./internal/scanner -run "Test.*Fast.*|Test.*Real.*" -json 2>/dev/null | jq -r 'select(.Action=="pass") | .Action' | wc -l || echo 0)
FAILED=$(go test -tags=integration -timeout=2m ./internal/scanner -run "Test.*Fast.*|Test.*Real.*" -json 2>/dev/null | jq -r 'select(.Action=="fail") | .Action' | wc -l || echo 0)
SKIPPED=$(go test -tags=integration -timeout=2m ./internal/scanner -run "Test.*Fast.*|Test.*Real.*" -json 2>/dev/null | jq -r 'select(.Action=="skip") | .Action' | wc -l || echo 0)

echo "Total tests: $TOTAL"
echo "✓ Passed: $PASSED"
if [ "$FAILED" -gt 0 ]; then
    echo "✗ Failed: $FAILED"
else
    echo "✗ Failed: 0"
fi
echo "⚠ Skipped: $SKIPPED"

# Exit with error if any tests failed
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi