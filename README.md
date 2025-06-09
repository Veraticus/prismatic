# Prismatic

[![CI](https://github.com/Veraticus/prismatic/actions/workflows/ci.yml/badge.svg)](https://github.com/Veraticus/prismatic/actions/workflows/ci.yml)
[![Security](https://github.com/Veraticus/prismatic/actions/workflows/security.yml/badge.svg)](https://github.com/Veraticus/prismatic/actions/workflows/security.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Veraticus/prismatic)](https://goreportcard.com/report/github.com/Veraticus/prismatic)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

🔍 **Prismatic** is a unified security scanning orchestrator that combines multiple open-source security tools into comprehensive, beautiful reports. It provides a single interface to run various security scanners across your cloud infrastructure, containers, and code repositories.

## 🌟 Features

- **Multi-Scanner Integration**: Seamlessly orchestrates 6+ industry-standard security tools
- **Beautiful Reports**: Generates AI-readable HTML and PDF reports with a professional "prismatic" theme
- **Two-Phase Operation**: Separate scanning and reporting phases for maximum flexibility
- **Smart Finding Management**: 
  - Suppress false positives with expiration dates
  - Override severities based on your risk assessment
  - Add comments and business context to findings
- **Business Context Enrichment**: Add ownership, data classification, and compliance metadata
- **Deterministic Finding IDs**: Consistent IDs enable reliable suppression and tracking
- **Parallel Execution**: Runs multiple scanners concurrently for faster results

## 🔧 Supported Scanners

| Scanner | Purpose | Target |
|---------|---------|--------|
| **[Prowler](https://github.com/prowler-cloud/prowler)** | AWS security best practices and compliance | AWS accounts, regions, services |
| **[Trivy](https://github.com/aquasecurity/trivy)** | Container and artifact vulnerabilities | Docker images, ECR, filesystems |
| **[Kubescape](https://github.com/kubescape/kubescape)** | Kubernetes security posture | K8s clusters, namespaces |
| **[Nuclei](https://github.com/projectdiscovery/nuclei)** | Web vulnerability scanning | HTTP/HTTPS endpoints |
| **[Gitleaks](https://github.com/zricethezav/gitleaks)** | Secret and credential detection | Git repositories |
| **[Checkov](https://github.com/bridgecrewio/checkov)** | Infrastructure as Code security | Terraform, CloudFormation, K8s manifests |

## 📋 Prerequisites

- Go 1.21 or higher
- Git
- Docker (for container scanning)
- kubectl (for Kubernetes scanning)
- AWS CLI configured (for AWS scanning)

### Installing Security Tools

Prismatic requires the actual security scanning tools to be installed on your system:

```bash
# Check which scanners are installed and get installation instructions
./scripts/install-scanners.sh
```

This script will:
- ✅ Check which scanners are already installed
- 📋 Provide specific installation commands for missing tools
- 🔧 Verify additional requirements (Docker, kubectl, AWS CLI)

**Manual Installation:**

If you prefer to install specific tools manually:

| Tool | Installation |
|------|-------------|
| **Prowler** | `pip install prowler` or `pipx install prowler` |
| **Trivy** | `brew install aquasecurity/trivy/trivy` (macOS) |
| **Kubescape** | `curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh \| /bin/bash` |
| **Nuclei** | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **Gitleaks** | `brew install gitleaks` (macOS) or download from [releases](https://github.com/zricethezav/gitleaks/releases) |
| **Checkov** | `pip install checkov` or `brew install checkov` |

**Note:** You only need to install the scanners you plan to use. For example, if you're only scanning AWS, you just need Prowler.

## 🚀 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/Veraticus/prismatic.git
cd prismatic

# Build the binary
make build

# Run tests
make test

# Install to PATH
sudo cp prismatic /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/Veraticus/prismatic/cmd/prismatic@latest
```

## 🎯 Quick Start

### 1. Create a Configuration File

Create a YAML configuration file for your environment:

```yaml
# mycompany.yaml
client:
  name: MyCompany
  environment: production
  description: "Production security scan"

# AWS Configuration
aws:
  profiles:
    - production-profile
  regions:
    - us-east-1
    - us-west-2

# Container Configuration
containers:
  registries:
    - type: ecr
      region: us-east-1
      registry: "123456789012.dkr.ecr.us-east-1.amazonaws.com"
  images:
    - name: web-app
      image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/web-app:v1.2.3"
    - name: api-service
      image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/api:latest"

# Kubernetes Configuration
kubernetes:
  kubeconfig: "~/.kube/production-config"  # Optional: path to kubeconfig
  contexts:
    - production-eks-cluster
  namespaces: []  # Empty = scan all namespaces

# Web Endpoints
web_endpoints:
  - name: main-website
    url: "https://www.example.com"
  - name: api-endpoint
    url: "https://api.example.com"
  - name: admin-panel
    url: "https://admin.example.com"

# Git Repositories
repositories:
  - name: backend
    path: "https://github.com/mycompany/backend"
    branch: main
  - name: frontend
    path: "https://github.com/mycompany/frontend"
    branch: main
  - name: infrastructure
    path: "https://github.com/mycompany/infrastructure"
    branch: main

# Scanner Configuration
scanners:
  prowler:
    enabled: true
  trivy:
    enabled: true
  kubescape:
    enabled: true
  nuclei:
    enabled: true
  gitleaks:
    enabled: true
  checkov:
    enabled: true

# Output Configuration
output:
  format: html  # or pdf
  directory: "./reports/mycompany"
```

### 2. Run a Security Scan

```bash
# Run all configured scanners
prismatic scan -c mycompany.yaml

# Run specific scanners only
prismatic scan -c mycompany.yaml --only prowler,trivy

# Run with increased verbosity
prismatic scan -c mycompany.yaml -v

# Run with custom timeout (in seconds)
prismatic scan -c mycompany.yaml --timeout 3600
```

### 3. Generate Reports

```bash
# Generate HTML report from the latest scan
prismatic report -c mycompany.yaml

# Generate PDF report
prismatic report -c mycompany.yaml --format pdf

# List available scans
prismatic list -c mycompany.yaml

# Generate report from specific scan
prismatic report -c mycompany.yaml --scan-id 2025-01-15-103045
```

## 🔍 Repository Scanning

Prismatic automatically clones and scans Git repositories for secrets (using Gitleaks) and Infrastructure-as-Code issues (using Checkov). This feature supports both remote Git URLs and local paths.

### Remote Repository Scanning

When you configure remote repositories, Prismatic will:
1. Clone each repository to a temporary directory
2. Check out the specified branch
3. Run Gitleaks and Checkov on the code
4. Clean up the cloned repositories after scanning

```yaml
repositories:
  - name: backend-api
    path: "https://github.com/mycompany/backend"
    branch: main
  - name: frontend-app
    path: "https://github.com/mycompany/frontend"  
    branch: develop
  - name: terraform-configs
    path: "git@github.com:mycompany/infrastructure.git"
    branch: production
```

### Local Repository Scanning

You can also scan repositories that are already cloned locally:

```yaml
repositories:
  - name: backend-api
    path: "/home/developer/projects/backend"
    branch: main  # Will check out this branch
  - name: frontend-app
    path: "./frontend"  # Relative paths are supported
    branch: develop
  - name: current-repo
    path: "."  # Scan the current directory
    branch: main
```

### Private Repository Access

For private repositories, ensure your Git credentials are configured:

```bash
# SSH authentication (recommended)
ssh-add ~/.ssh/id_rsa

# HTTPS with credentials
git config --global credential.helper store

# For GitHub, use personal access tokens
export GITHUB_TOKEN=your-token-here
```

### Repository Scan Results

Repository findings include:
- **Repository context**: Each finding shows which repository it came from
- **File location**: Exact file and line number
- **Secret detection**: API keys, passwords, tokens (Gitleaks)
- **IaC misconfigurations**: Security issues in Terraform, CloudFormation, Kubernetes manifests (Checkov)

Example finding:
```
🔴 CRITICAL: Exposed AWS Access Key
Repository: backend-api:src/config/aws.js
Line: 42
Description: AWS access key found in source code
Remediation: Remove the key from code and rotate it immediately
```

### Advanced Repository Options

```yaml
# Coming soon: Additional repository options
repositories:
  - name: monorepo
    path: "https://github.com/mycompany/monorepo"
    branch: main
    # Future features:
    # subpath: "services/api"  # Scan only specific directory
    # shallow: false           # Full clone vs shallow clone
    # exclude: ["test/", "vendor/"]  # Exclude paths from scanning
```

## 📊 Report Features

Prismatic generates professional reports featuring:

### Executive Summary
- Total findings by severity
- Scanner coverage status
- Top security risks
- Suppressed findings count

### Detailed Findings
Each finding includes:
- **Severity Badge**: Color-coded with gemstone theme
- **Resource Identification**: What was affected
- **Description**: Clear explanation of the issue
- **Impact Assessment**: Business and technical impact
- **Remediation Steps**: How to fix the issue
- **Business Context**: Owner, data classification, compliance impact
- **Audit Trail**: Original severity, modifications, comments

### Visual Design
Reports use a "prismatic" light-refraction theme with:
- 🔴 **Critical**: Ruby red (#9b111e)
- 🟠 **High**: Amber orange (#ff6700)
- 🟡 **Medium**: Topaz yellow (#ffd700)
- 🔵 **Low**: Sapphire blue (#4169e1)
- ⚪ **Info**: Pearl gray (#708090)

## 🛡️ Finding Management

### Suppressions

Suppress false positives or accepted risks:

```yaml
# In your config file
suppressions:
  # Suppress specific finding types by scanner
  prowler:
    - "s3_bucket_public_read_access"  # Public website bucket
    - "cloudfront_tls_version"         # Legacy app compatibility
  
  trivy:
    - "CVE-2023-12345"  # False positive in test code
  
  # Global suppressions
  global:
    date_before: "2024-01-01"  # Ignore old findings
```

### Severity Overrides

Adjust severities based on your risk context:

```yaml
severity_overrides:
  # Reduce severity for dev environment
  "s3_bucket_versioning_disabled": "low"      # Was: medium
  "ec2_instance_public_ip": "medium"          # Was: high
  
  # Increase severity for critical resources  
  "rds_backup_disabled": "critical"           # Was: high
  "iam_user_no_mfa": "high"                  # Was: medium
```

### Business Context Enrichment

Add metadata for better prioritization:

```yaml
metadata_enrichment:
  resources:
    # S3 bucket with customer data
    "arn:aws:s3:::customer-uploads":
      owner: "data-team"
      data_classification: "confidential"
      business_impact: "Customer PII storage"
      compliance_impact: ["GDPR", "CCPA"]
    
    # Production database
    "arn:aws:rds:us-east-1:123456789012:db:prod-db":
      owner: "platform-team"
      data_classification: "restricted"
      business_impact: "Primary customer database"
      compliance_impact: ["PCI-DSS", "SOC2", "HIPAA"]
    
    # Public website
    "https://www.example.com":
      owner: "marketing-team"
      data_classification: "public"
      business_impact: "Company website"
```

### Manual Modifications

Make changes to findings after scanning:

```bash
# List all findings
prismatic modifications list -c mycompany.yaml

# Suppress a finding
prismatic modifications suppress <finding-id> \
  -c mycompany.yaml \
  --reason "False positive - test environment only" \
  --expires "2025-12-31"

# Change severity
prismatic modifications severity <finding-id> low \
  -c mycompany.yaml \
  --reason "Mitigated by compensating controls"

# Add a comment
prismatic modifications comment <finding-id> \
  -c mycompany.yaml \
  --comment "Scheduled for remediation in Q2 2025"

# Apply all modifications and regenerate report
prismatic modifications apply -c mycompany.yaml
```

## 🔧 Advanced Configuration

### Full Configuration Example

See [configs/example-with-enrichment.yaml](configs/example-with-enrichment.yaml) for a complete configuration example with all features.

### Environment Variables

```bash
# AWS authentication
export AWS_PROFILE=production
export AWS_REGION=us-east-1

# Kubernetes authentication  
export KUBECONFIG=/path/to/kubeconfig

# Prismatic settings
export PRISMATIC_LOG_LEVEL=debug
export PRISMATIC_TIMEOUT=3600
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Run Prismatic Security Scan
  run: |
    prismatic scan -c production.yaml
    prismatic report -c production.yaml --format html
    
- name: Upload Security Report
  uses: actions/upload-artifact@v3
  with:
    name: security-report
    path: reports/**/*.html
```

## 🛠️ Development

### Project Structure

```
prismatic/
├── cmd/                    # CLI commands
│   ├── prismatic/         # Main entry point
│   ├── scan/              # Scan command
│   ├── report/            # Report generation
│   ├── list/              # List scans
│   └── modifications/     # Manage findings
├── internal/
│   ├── scanner/           # Scanner implementations
│   ├── models/            # Core data models
│   ├── report/            # Report generation
│   ├── storage/           # Data persistence
│   └── config/            # Configuration
├── configs/               # Example configurations
├── scripts/               # Utility scripts
└── test/                  # Test fixtures
```

### Building and Testing

```bash
# Run all tests
make test

# Run tests with race detection
make test-race

# Generate coverage report
make test-coverage

# Run linter (must pass with 0 issues)
make lint

# Format code
make fmt

# Auto-fix common issues
make fix

# Run all checks (fmt, vet, lint, test)
make check

# Build for all platforms
make build-all

# Quick development workflow
make quick    # Format and test
make test-all # Comprehensive tests with all checks
```

### Adding a New Scanner

1. Create scanner implementation in `internal/scanner/yourscanner.go`
2. Implement the `Scanner` interface:
   ```go
   type Scanner interface {
       Name() string
       Scan(ctx context.Context) (*models.ScanResult, error)
       ParseResults(raw []byte) ([]models.Finding, error)
   }
   ```
3. Embed the `BaseScanner` for common functionality:
   ```go
   type YourScanner struct {
       *BaseScanner
       // scanner-specific fields
   }
   ```
4. Use the `SimpleScan` method if your scanner follows common patterns:
   ```go
   func (s *YourScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
       return s.BaseScanner.SimpleScan(ctx, SimpleScanOptions{
           ScannerName:     s.Name(),
           GetVersion:      s.getVersion,
           Iterator:        NewSimpleTargetIterator(s.targets, nil),
           ScanTarget:      s.scanSingleTarget,
           ParseOutput:     s.ParseResults,
           ContinueOnError: true,
       })
   }
   ```
5. Add to factory in `internal/scanner/factory.go`
6. Update configuration structures
7. Add comprehensive tests following Go idioms
8. Update documentation

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow standard Go conventions and idioms
- Run `make lint` before committing - must pass with 0 issues
- Run `make fix` to auto-fix common issues  
- Add tests for new functionality using table-driven tests
- Avoid over-abstraction - prefer clarity over cleverness
- Update documentation as needed

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Prismatic wouldn't be possible without these excellent open-source security tools:
- [Prowler](https://github.com/prowler-cloud/prowler) - AWS Security Best Practices
- [Trivy](https://github.com/aquasecurity/trivy) - Container Security
- [Kubescape](https://github.com/kubescape/kubescape) - Kubernetes Security
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Web Security
- [Gitleaks](https://github.com/zricethezav/gitleaks) - Secret Detection
- [Checkov](https://github.com/bridgecrewio/checkov) - IaC Security

## 📞 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/Veraticus/prismatic/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/Veraticus/prismatic/discussions)
- 📖 **Wiki**: [GitHub Wiki](https://github.com/Veraticus/prismatic/wiki)

---

<p align="center">
Made with ❤️ by <a href="https://github.com/Veraticus">Veraticus</a>
</p>