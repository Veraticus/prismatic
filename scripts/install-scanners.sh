#!/usr/bin/env bash
# install-scanners.sh - Install required security scanning tools for prismatic

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track installation status
INSTALLED=()
FAILED=()
SKIPPED=()

echo "Installing security scanning tools for Prismatic..."
echo "=============================================="
echo ""

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install a tool
install_tool() {
    local name=$1
    local check_command=${2:-$1}
    
    echo -n "Checking $name... "
    
    if command_exists "$check_command"; then
        echo -e "${GREEN}✓ already installed${NC}"
        INSTALLED+=("$name")
        return 0
    else
        echo -e "${YELLOW}not found${NC}"
        return 1
    fi
}

# Function to print installation instructions
print_instructions() {
    local tool=$1
    shift
    echo ""
    echo -e "${YELLOW}To install $tool:${NC}"
    for instruction in "$@"; do
        echo "  $instruction"
    done
    echo ""
    FAILED+=("$tool")
}

echo "Checking installed scanners:"
echo "----------------------------"

# Check Prowler
if ! install_tool "Prowler" "prowler"; then
    print_instructions "Prowler" \
        "pip install prowler" \
        "# or" \
        "pipx install prowler"
fi

# Check Trivy
if ! install_tool "Trivy" "trivy"; then
    if [[ "$OS" == "macos" ]]; then
        print_instructions "Trivy" \
            "brew install aquasecurity/trivy/trivy"
    else
        print_instructions "Trivy" \
            "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin" \
            "# or" \
            "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -" \
            "echo \"deb https://aquasecurity.github.io/trivy-repo/deb generic main\" | sudo tee -a /etc/apt/sources.list.d/trivy.list" \
            "sudo apt-get update && sudo apt-get install trivy"
    fi
fi

# Check Kubescape
if ! install_tool "Kubescape" "kubescape"; then
    print_instructions "Kubescape" \
        "curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash" \
        "# or" \
        "brew install kubescape/tap/kubescape"
fi

# Check Nuclei
if ! install_tool "Nuclei" "nuclei"; then
    print_instructions "Nuclei" \
        "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
        "# or" \
        "brew install nuclei"
fi

# Check Gitleaks
if ! install_tool "Gitleaks" "gitleaks"; then
    if [[ "$OS" == "macos" ]]; then
        print_instructions "Gitleaks" \
            "brew install gitleaks"
    else
        print_instructions "Gitleaks" \
            "# Download from https://github.com/zricethezav/gitleaks/releases" \
            "# or" \
            "go install github.com/zricethezav/gitleaks/v8@latest"
    fi
fi

# Check Checkov
if ! install_tool "Checkov" "checkov"; then
    print_instructions "Checkov" \
        "pip install checkov" \
        "# or" \
        "pipx install checkov" \
        "# or" \
        "brew install checkov"
fi

# Summary
echo ""
echo "Installation Summary"
echo "===================="

if [ ${#INSTALLED[@]} -gt 0 ]; then
    echo -e "${GREEN}✓ Already installed:${NC}"
    for tool in "${INSTALLED[@]}"; do
        echo "  - $tool"
    done
fi

if [ ${#FAILED[@]} -gt 0 ]; then
    echo ""
    echo -e "${RED}✗ Need to install:${NC}"
    for tool in "${FAILED[@]}"; do
        echo "  - $tool"
    done
    echo ""
    echo "Please install the missing tools using the instructions above."
    echo ""
    echo "For more detailed installation guides, visit:"
    echo "  - Prowler: https://docs.prowler.cloud/en/latest/getting-started/installation/"
    echo "  - Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    echo "  - Kubescape: https://hub.armosec.io/docs/installation"
    echo "  - Nuclei: https://nuclei.projectdiscovery.io/nuclei/get-started/"
    echo "  - Gitleaks: https://github.com/zricethezav/gitleaks#installing"
    echo "  - Checkov: https://www.checkov.io/2.Basics/Installing%20Checkov.html"
    exit 1
else
    echo ""
    echo -e "${GREEN}✅ All scanners are installed and ready to use!${NC}"
fi

# Check for additional requirements
echo ""
echo "Additional Requirements"
echo "======================"

# Check Docker
echo -n "Docker (for container scanning): "
if command_exists "docker"; then
    echo -e "${GREEN}✓ installed${NC}"
else
    echo -e "${YELLOW}⚠ not found${NC} (required for scanning container images)"
fi

# Check kubectl
echo -n "kubectl (for Kubernetes scanning): "
if command_exists "kubectl"; then
    echo -e "${GREEN}✓ installed${NC}"
else
    echo -e "${YELLOW}⚠ not found${NC} (required for scanning Kubernetes clusters)"
fi

# Check AWS CLI
echo -n "AWS CLI (for AWS scanning): "
if command_exists "aws"; then
    echo -e "${GREEN}✓ installed${NC}"
else
    echo -e "${YELLOW}⚠ not found${NC} (required for scanning AWS resources and ECR)"
fi

echo ""
echo "Note: Make sure you have appropriate credentials configured for:"
echo "  - AWS CLI: run 'aws configure' or set AWS_PROFILE"
echo "  - kubectl: ensure your kubeconfig is set up"
echo "  - Docker: ensure you're logged in to any private registries"