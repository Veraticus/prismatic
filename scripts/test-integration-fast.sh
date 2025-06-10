#!/bin/bash
# Fast integration testing script for Nuclei and Checkov

set -e

echo "=== Fast Integration Testing for Security Scanners ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${YELLOW}Warning: $1 not found in PATH. Skipping $1 tests.${NC}"
        return 1
    fi
    return 0
}

# Nuclei fast test
if check_tool "nuclei"; then
    echo -e "${GREEN}Testing Nuclei with minimal templates...${NC}"
    
    # Create a test target file
    echo "http://scanme.nmap.org" > /tmp/nuclei-test-targets.txt
    
    # Run with minimal templates - should complete in under 5 seconds
    time nuclei \
        -l /tmp/nuclei-test-targets.txt \
        -tags tech \
        -severity info \
        -timeout 3 \
        -rate-limit 100 \
        -c 10 \
        -duc \
        -silent \
        -stats
    
    echo ""
fi

# Checkov fast test
if check_tool "checkov"; then
    echo -e "${GREEN}Testing Checkov with minimal checks...${NC}"
    
    # Create a test directory with a simple Terraform file
    TEST_DIR=$(mktemp -d)
    cat > "$TEST_DIR/main.tf" << 'EOF'
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
EOF
    
    # Run with specific checks - should complete in under 5 seconds
    time checkov \
        -d "$TEST_DIR" \
        --framework terraform \
        --check CKV_AWS_18,CKV_AWS_24 \
        --output cli \
        --quiet \
        --compact
    
    # Cleanup
    rm -rf "$TEST_DIR"
    echo ""
fi

# Run Go integration tests if both tools are available
if check_tool "nuclei" && check_tool "checkov"; then
    echo -e "${GREEN}Running Go integration tests...${NC}"
    
    # Run the fast integration tests
    go test -tags integration -v ./internal/scanner -run "TestNucleiIntegrationMinimal|TestCheckovIntegrationMinimal" -timeout 30s
fi

echo ""
echo "=== Example Commands for Manual Testing ==="
echo ""
echo "Nuclei - Technology Detection (1-2 seconds):"
echo "  nuclei -u https://example.com -tags tech -rl 100 -c 50 -timeout 3"
echo ""
echo "Nuclei - Specific CVEs (2-3 seconds):"
echo "  nuclei -u https://example.com -t cves/2023/ -severity critical,high -rl 50"
echo ""
echo "Checkov - High Severity Only (1-2 seconds):"
echo "  checkov -d . --framework terraform --check HIGH --output json --quiet"
echo ""
echo "Checkov - Specific Checks (<1 second):"
echo "  checkov -d . --check CKV_AWS_18,CKV_AWS_24 --output json --compact"