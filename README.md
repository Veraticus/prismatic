# Prismatic

[![CI](https://github.com/Veraticus/prismatic/actions/workflows/ci.yml/badge.svg)](https://github.com/Veraticus/prismatic/actions/workflows/ci.yml)
[![Security](https://github.com/Veraticus/prismatic/actions/workflows/security.yml/badge.svg)](https://github.com/Veraticus/prismatic/actions/workflows/security.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Veraticus/prismatic)](https://goreportcard.com/report/github.com/Veraticus/prismatic)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

🔍 **Prismatic** is a unified security scanning orchestrator that combines multiple open-source security tools into comprehensive, beautiful reports. It provides an intuitive terminal UI (TUI) to run various security scanners across your cloud infrastructure, containers, and code repositories.

### ✨ What's New

- **🤖 AI-Powered Enrichment**: Enhance findings with business context using LLMs
- **🔧 Automated Remediation**: Generate fix bundles with patches, validation scripts, and LLM prompts
- **📊 Smart Batching**: Cost-effective AI enrichment strategies
- **🎯 Actionable Outputs**: From scanning to fixing in one workflow

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
- **AI-Powered Enrichment**: Enhance findings with business context using LLMs
- **Remediation Generation**: Create actionable fix bundles with code patches and validation scripts

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
git clone https://github.com/joshsymonds/prismatic.git
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
go install github.com/joshsymonds/prismatic/cmd/prismatic@latest
```

## 🎯 Quick Start

### Launch Prismatic

```bash
# Start the interactive TUI
prismatic

# Or with debug logging
prismatic --debug
```

### Using the TUI

Prismatic provides an intuitive terminal interface for all operations:

1. **Main Menu**
   - `New Scan` - Configure and run security scans
   - `Scan History` - View previous scans and generate reports
   - `Results Browser` - Browse and analyze findings
   - `Reports` - Access generated reports
   - `Settings` - Configure preferences

2. **Keyboard Navigation**
   - `↑/↓` or `j/k` - Navigate menus
   - `Enter` - Select item
   - `Esc` - Go back
   - `q` - Quit (from main menu)

3. **Scan Configuration**
   - Select scanners to run
   - Configure scanner-specific settings
   - Set targets (AWS accounts, containers, etc.)
   - Start scan with real-time progress

4. **Report Generation**
   - From Scan History, press `r` to generate HTML report
   - Press `e` to enrich findings with AI analysis
   - Reports are saved in the `reports/` directory
prismatic enrich -s data/scans/latest --model haiku
```

#### 3. Generate Reports and Remediation

```bash
5. **Features**
   - All scanner configuration through the TUI
   - Real-time scan progress monitoring
   - SQLite database for all data storage
   - No YAML configuration files needed
   - Integrated report generation
   - AI enrichment support (coming soon)
```


## 🤖 AI-Powered Enrichment

Prismatic can enhance your security findings with business context using AI/LLM providers. This helps prioritize remediation efforts by understanding the real-world impact of each finding.

### Enrichment Features

- **Business Impact Analysis**: Understand how security issues affect your business
- **Compliance Mapping**: Link findings to regulatory requirements (GDPR, PCI-DSS, HIPAA)
- **Exploitation Context**: Get real-world exploitation likelihood and attack scenarios
- **Remediation Guidance**: Detailed, context-aware fix recommendations

### 🔥 Claude Code Integration

Prismatic has **native integration with Claude Code**, making it the preferred choice for enrichment:

#### Prerequisites

Ensure you have Claude Code installed:
```bash
# Check if claude is available
claude --version

# If not installed, visit: https://claude.ai/code
```

#### How It Works

1. **Direct CLI Integration**: Prismatic uses the `claude` CLI command directly
2. **Intelligent Batching**: Groups similar findings to minimize token usage
3. **Structured Output**: Claude returns JSON-formatted enrichments
4. **Model Selection**: Choose between Opus (best), Sonnet (balanced), or Haiku (fast)

#### Running Enrichment with Claude

```bash
# Default: Uses Claude Sonnet for balanced cost/quality
prismatic enrich -s data/scans/latest

# Use Claude Opus for highest quality analysis
prismatic enrich -s data/scans/latest --driver claude-cli --model opus

# Use Claude Haiku for fastest, most cost-effective analysis
prismatic enrich -s data/scans/latest --driver claude-cli --model haiku

# Different strategies to control costs
prismatic enrich -s data/scans/latest --strategy critical-only  # Only critical findings
prismatic enrich -s data/scans/latest --strategy high-impact    # Critical + High
prismatic enrich -s data/scans/latest --strategy smart-batch    # Groups similar findings
```

#### Example Claude Enrichment Output

When you run enrichment, Claude analyzes each finding and provides:

```json
{
  "finding_id": "prowler-s3-001",
  "analysis": {
    "business_impact": "Customer PII at risk - S3 bucket contains user uploads with personal data",
    "priority_score": 9.5,
    "priority_reasoning": "Public access + sensitive data + easy to exploit = critical priority",
    "technical_details": "Bucket ACL allows s3:GetObject from principal '*', exposing all objects",
    "contextual_notes": "This bucket processes 10K user uploads daily including ID documents"
  },
  "remediation": {
    "immediate": [
      "Block public access immediately: aws s3api put-public-access-block --bucket user-uploads",
      "Enable access logging to check for unauthorized access"
    ],
    "short_term": [
      "Implement bucket policies restricting access to specific IAM roles",
      "Enable S3 Object Lock for compliance"
    ],
    "long_term": [
      "Migrate to S3 Access Points for fine-grained access control",
      "Implement automated compliance scanning"
    ],
    "estimated_effort": "2 hours immediate, 1 day short-term",
    "automation_possible": true,
    "validation_steps": [
      "Run: aws s3api get-public-access-block --bucket user-uploads",
      "Verify all four block settings are 'true'"
    ]
  }
}
```

#### Cost Optimization

Claude pricing (approximate):
- **Opus**: ~$15 per 1M input tokens (highest quality)
- **Sonnet**: ~$3 per 1M input tokens (recommended)
- **Haiku**: ~$0.25 per 1M input tokens (fastest)

Token usage examples:
- 100 findings ≈ 50K tokens with smart batching
- 1000 findings ≈ 200K tokens with critical-only strategy

#### Configuration

```yaml
# configs/mycompany.yaml
enrichment:
  driver: "claude-cli"  # Use Claude Code
  model: "sonnet"       # opus, sonnet, or haiku
  temperature: 0.3      # Lower = more consistent
  
  # Cost controls
  strategy: "smart-batch"
  token_budget: 100000  # Maximum tokens per run
  
  # Caching
  cache_ttl: "30d"      # Reuse enrichments for 30 days
```

### Enrichment Strategies

| Strategy | Description | Use Case | Token Efficiency |
|----------|-------------|----------|------------------|
| `all` | Enrich every finding | Complete analysis | Low |
| `critical-only` | Only critical severity | Cost-conscious | Very High |
| `high-impact` | Critical and high severity | Balanced approach | High |
| `smart-batch` | Group similar findings | Most efficient | Highest |

### Knowledge Base Integration

Enhance Claude's analysis with your organization's context:

```yaml
# knowledge/services.yaml
services:
  user-api:
    description: "Main user authentication and profile API"
    business_impact: "Critical - affects all user logins"
    data_sensitivity: "PII, authentication tokens"
    compliance_scope: ["GDPR", "CCPA"]
    owner: "identity-team"
    sla: "99.99% uptime required"

# knowledge/infrastructure.yaml  
infrastructure:
  production-vpc:
    description: "Primary production VPC in us-east-1"
    criticality: "high"
    data_classification: "sensitive"
    connected_services: ["user-api", "payment-api", "analytics"]
```

Claude will use this context to provide more accurate business impact assessments.

## 🔧 Remediation Generation

Prismatic can generate actionable remediation plans and fix bundles from your security findings.

### Remediation Formats

#### 1. Remediation Manifest (YAML)

Machine-readable action plan:

```bash
prismatic report -s data/scans/latest --format remediation -o fixes.yaml
```

Output includes:
- Grouped findings by fix strategy
- Prioritized remediation tasks
- Effort estimates
- Implementation instructions
- Validation steps

#### 2. Fix Bundle (Complete Package)

Ready-to-apply fixes with validation:

```bash
prismatic report -s data/scans/latest --format fix-bundle -o fix-bundle/
```

Creates:
```
fix-bundle/
├── manifest.yaml                    # Remediation plan
├── README.md                        # Priority-ordered tasks
├── remediations/
│   ├── rem-001-s3-public-access/
│   │   ├── README.md               # Fix instructions
│   │   ├── fix.patch               # Git patch
│   │   ├── terraform/              # IaC fixes
│   │   │   └── s3_public_access_block.tf
│   │   ├── validation.sh           # Verify fix worked
│   │   └── llm-prompt.txt          # AI assistant prompt
│   └── rem-002-cve-updates/
│       └── ...
└── scripts/
    ├── apply-all-critical.sh       # Bulk apply critical fixes
    └── validate-all.sh             # Verify all fixes
```

### Using Fix Bundles

```bash
# Review the fix bundle
cd fix-bundle/
cat README.md

# Apply critical fixes
./scripts/apply-all-critical.sh

# Or apply individual fixes
cd remediations/rem-001-s3-public-access/
cat README.md
# Review and apply the terraform changes
cp terraform/* ~/infrastructure/

# Validate the fix
./validation.sh
```

### LLM-Assisted Remediation

Each remediation includes an LLM prompt for AI-assisted fixing:

```bash
# Use with Claude, ChatGPT, or other AI coding assistants
cat fix-bundle/remediations/rem-001-s3-public-access/llm-prompt.txt | claude
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

## 🔐 Scanner Configuration

### Enabling/Disabling Scanners

You can control which scanners run by using the `scanners` configuration section. By default, all scanners are enabled if their required resources are configured.

```yaml
# Disable specific scanners
scanners:
  prowler:
    enabled: true   # Scan AWS infrastructure
  trivy:
    enabled: true   # Scan containers
  kubescape:
    enabled: false  # Skip Kubernetes scanning
  nuclei:
    enabled: true   # Scan web endpoints
  gitleaks:
    enabled: true   # Scan for secrets
  checkov:
    enabled: false  # Skip IaC scanning
```

**Key points:**
- If no `scanners` section is provided, all scanners are enabled by default
- Scanners set to `enabled: false` will be completely skipped (no output, no status)
- This setting overrides the `--only` command line flag
- Disabled scanners won't appear in reports or status outputs

**Use cases:**
- **Performance**: Disable scanners you don't need to speed up scans
- **Licensing**: Disable scanners that require specific licenses or permissions
- **Testing**: Focus on specific security areas during development
- **Environment-specific**: Different scanner sets for dev/staging/production

Example: Development environment with minimal scanning:

```yaml
# dev-config.yaml
client:
  name: MyCompany
  environment: development

# Only scan repositories in dev
repositories:
  - name: backend
    path: "./backend"
    branch: develop

# Disable cloud scanners in development
scanners:
  prowler:
    enabled: false  # No AWS in dev
  trivy:
    enabled: false  # No containers in dev
  kubescape:
    enabled: false  # No K8s in dev
  nuclei:
    enabled: false  # No web scanning in dev
  gitleaks:
    enabled: true   # Always scan for secrets
  checkov:
    enabled: true   # Always check IaC
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

## 🔍 Troubleshooting Claude Integration

### Common Issues

#### Claude CLI Not Found
```bash
# Error: claude CLI not found or not working
# Solution: Ensure Claude Code is installed
claude --version

# If not installed, visit: https://claude.ai/code
```

#### Token Limit Exceeded
```bash
# Error: Token budget exceeded
# Solution 1: Use a more efficient strategy
prismatic enrich -s data/scans/latest --strategy critical-only

# Solution 2: Increase token budget
prismatic enrich -s data/scans/latest --token-budget 200000
```

#### Slow Enrichment
```bash
# Use Haiku model for faster processing
prismatic enrich -s data/scans/latest --model haiku

# Enable caching to skip already-enriched findings
prismatic enrich -s data/scans/latest --use-cache
```

#### JSON Parsing Errors
```bash
# Error: Failed to parse claude response
# Solution: Use lower temperature for more consistent output
prismatic enrich -s data/scans/latest --temperature 0.1
```

### Best Practices

1. **Start Small**: Test with critical findings first
2. **Use Caching**: Enrichments are cached for 30 days by default
3. **Monitor Costs**: Check token usage in enrichment metadata
4. **Batch Wisely**: Smart-batch strategy reduces tokens by 60-80%

## 📚 Command Reference

### Core Commands

```bash
# Scanning
prismatic scan                      # Interactive scanner selection
prismatic scan -c config.yaml       # Run configured scanners
prismatic scan --only prowler,trivy # Run specific scanners

# Enrichment
prismatic enrich -s data/scans/latest                    # Enrich all findings
prismatic enrich -s data/scans/latest --strategy critical-only  # Cost-effective
prismatic enrich -s data/scans/latest --use-cache       # Use cached results

# Reporting
prismatic report -s data/scans/latest --format html -o report.html
prismatic report -s data/scans/latest --format pdf -o report.pdf
prismatic report -s data/scans/latest --format remediation -o fixes.yaml
prismatic report -s data/scans/latest --format fix-bundle -o fix-bundle/

# Management
prismatic list -c config.yaml                    # List all scans
prismatic config validate -c config.yaml         # Validate configuration
prismatic modifications list -c config.yaml      # List finding modifications
```

### Report Formats

| Format | Output | Purpose |
|--------|--------|---------|
| `html` | Single HTML file | Human review, compliance |
| `pdf` | PDF document | Archival, distribution |
| `remediation` | YAML manifest | Machine-readable fixes |
| `fix-bundle` | Directory structure | Complete fix package |

## 🛠️ Development

### Project Structure

```
prismatic/
├── cmd/                    # CLI commands
│   ├── prismatic/         # Main entry point
│   ├── scan/              # Scan command
│   ├── report/            # Report generation
│   ├── enrich/            # AI enrichment
│   ├── list/              # List scans
│   ├── config/            # Config validation
│   └── modifications/     # Manage findings
├── internal/
│   ├── scanner/           # Scanner implementations
│   ├── models/            # Core data models
│   ├── report/            # Report generation
│   ├── remediation/       # Fix generation
│   ├── enrichment/        # AI enrichment
│   ├── storage/           # Data persistence
│   └── config/            # Configuration
├── configs/               # Example configurations
├── scripts/               # Utility scripts
└── testdata/              # Test fixtures
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