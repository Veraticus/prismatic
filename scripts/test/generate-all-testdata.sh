#!/usr/bin/env bash
# Generate test data for all scanners

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Generating Test Data for All Scanners ==="
echo ""

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "⚠️  Warning: $1 is not installed. Skipping $1 test data generation."
        return 1
    fi
    return 0
}

# Generate Checkov data
if check_tool "checkov"; then
    echo "📊 Generating Checkov test data..."
    bash "$SCRIPT_DIR/generate-checkov-testdata.sh"
    echo ""
fi

# Generate Nuclei data
if check_tool "nuclei"; then
    echo "🎯 Generating Nuclei test data..."
    bash "$SCRIPT_DIR/generate-nuclei-testdata.sh"
    echo ""
fi

# Generate Gitleaks data
if check_tool "gitleaks"; then
    echo "🔑 Generating Gitleaks test data..."
    bash "$SCRIPT_DIR/generate-gitleaks-testdata.sh"
    echo ""
fi

# Generate Trivy data
if check_tool "trivy"; then
    echo "🐳 Generating Trivy test data..."
    bash "$SCRIPT_DIR/generate-trivy-testdata.sh"
    echo ""
fi

echo "=== Test Data Generation Complete ==="
echo "📁 All test data saved to: $(cd "$SCRIPT_DIR/../../testdata/scanner" && pwd)"