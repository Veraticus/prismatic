# Prismatic Security Scanner - Architecture Document

## Overview

Prismatic is a security scanning orchestrator that refracts multiple open-source security tools into a unified, beautiful report. It operates in two phases: scanning and report generation, allowing for manual review and adjustment of findings between phases.

## Core Architecture

### Design Principles
1. **Refraction Model**: Multiple security scanners (light sources) ? Prismatic (prism) ? Unified spectrum of findings (report)
2. **Two-Phase Operation**: Separate scanning from reporting for flexibility
3. **Client-Centric Configuration**: YAML configs per client/environment
4. **Claude Code Optimized**: HTML output designed for AI readability

### Project Structure
```
prismatic/
??? cmd/
?   ??? scan/          # Phase 1: Security scanning
?   ??? report/        # Phase 2: Report generation
??? internal/
?   ??? scanner/       # Scanner integrations
?   ?   ??? prowler.go
?   ?   ??? trivy.go
?   ?   ??? kubescape.go
?   ?   ??? nuclei.go
?   ?   ??? gitleaks.go
?   ?   ??? checkov.go
?   ??? models/        # Data structures
?   ??? config/        # Configuration handling
?   ??? report/        # Report generation
?       ??? html.go
?       ??? pdf.go     # Orchestrates HTML?PDF via headless browser
?       ??? templates/
??? configs/           # Client configurations
?   ??? example.yaml
?   ??? client-*.yaml
??? data/             # Scan results storage
?   ??? scans/
?       ??? YYYY-MM-DD-HHMMSS/
?           ??? metadata.json
?           ??? prowler.json
?           ??? trivy.json
?           ??? ...
??? go.mod
```

## Phase 1: Scanning (`prismatic scan`)

### Command Interface
```bash
prismatic scan \
  --config configs/client-acme.yaml \
  --output data/scans/2024-01-15-140000 \
  --aws-profile production \
  --k8s-context prod-cluster
```

### Client Configuration (YAML)
```yaml
# configs/client-acme.yaml
client:
  name: "ACME Corporation"
  environment: "Production"

aws:
  regions:
    - us-east-1
    - us-west-2
  profiles:
    - production
    - staging

docker:
  registries:
    - registry.acme.com
  containers:
    - api:latest
    - web:latest
    - worker:latest

kubernetes:
  contexts:
    - prod-cluster
    - staging-cluster
  namespaces:  # optional, scan all if not specified
    - default
    - production

endpoints:
  - https://api.acme.com
  - https://www.acme.com
  - https://admin.acme.com

suppressions:
  global:
    date_before: "2023-01-01"  # Ignore findings before this date
  
  trivy:
    - CVE-2021-3711      # Old Ruby OpenSSL
    - CVE-2021-23840     # Ruby version
    - GHSA-*             # Ignore GitHub advisories
  
  prowler:
    - iam_user_hardware_mfa_enabled  # Using SSO instead
    - s3_bucket_public_read_prohibited # Public website bucket
  
  kubescape:
    - C-0034  # Automatic mapping of service account
    - C-0035  # Cluster-admin binding
  
  nuclei:
    - exposed-panels/gitlab-detect
    - technologies/nginx-version
  
  gitleaks:
    - generic-api-key  # Too many false positives

severity_overrides:
  CVE-2021-3711: low     # Not exploitable in our context
  check_s3_encryption: medium  # Downgrade from high

metadata_enrichment:
  # Add business context to findings
  resources:
    "arn:aws:s3:::acme-public-website":
      owner: "Marketing Team"
      data_classification: "public"
    "api-deployment":
      owner: "Platform Team"
      data_classification: "confidential"
```

### Scanner Execution Flow
```go
// internal/scanner/orchestrator.go
type Orchestrator struct {
    config     *Config
    outputDir  string
    scanners   []Scanner
}

type Scanner interface {
    Name() string
    Scan(ctx context.Context) (*ScanResult, error)
    ParseResults(raw []byte) ([]Finding, error)
}

type ScanResult struct {
    Scanner   string    `json:"scanner"`
    Version   string    `json:"version"`
    StartTime time.Time `json:"start_time"`
    EndTime   time.Time `json:"end_time"`
    RawOutput []byte    `json:"-"`
    Findings  []Finding `json:"findings"`
    Error     string    `json:"error,omitempty"`
}

type Finding struct {
    ID              string            `json:"id"`  // Stable, deterministic hash - see below
    Scanner         string            `json:"scanner"`
    Type            string            `json:"type"`
    Severity        string            `json:"severity"`
    OriginalSeverity string           `json:"original_severity,omitempty"`
    Title           string            `json:"title"`
    Description     string            `json:"description"`
    Resource        string            `json:"resource"`
    Location        string            `json:"location,omitempty"`
    Framework       string            `json:"framework,omitempty"`
    Remediation     string            `json:"remediation"`
    Impact          string            `json:"impact"`
    References      []string          `json:"references"`
    Metadata        map[string]string `json:"metadata,omitempty"`
    Suppressed      bool              `json:"suppressed"`
    SuppressionReason string          `json:"suppression_reason,omitempty"`
}

// Stable Finding ID Generation
// The Finding.ID must be a deterministic hash to uniquely identify the same issue across scans.
// This enables reliable suppression and tracking without maintaining scan history.
func GenerateFindingID(f Finding) string {
    // Hash these core attributes that uniquely identify a finding:
    // - Scanner + Type + Resource + Location (if applicable)
    // Example: sha256("prowler:iam_root_no_mfa:arn:aws:iam::123456789012:root")
    core := fmt.Sprintf("%s:%s:%s:%s", f.Scanner, f.Type, f.Resource, f.Location)
    hash := sha256.Sum256([]byte(core))
    return hex.EncodeToString(hash[:8]) // First 8 bytes for readability
}
```

### Scan Output Structure
```
data/scans/2024-01-15-140000/
??? metadata.json       # Scan metadata and summary
??? raw/               # Raw scanner outputs (for debugging)
?   ??? prowler.json
?   ??? trivy.json
?   ??? ...
??? findings.json      # Normalized, enriched findings
??? scan.log          # Detailed execution log
```

## Phase 2: Report Generation (`prismatic report`)

### Command Interface
```bash
# Generate report from latest scan
prismatic report \
  --scan data/scans/2024-01-15-140000 \
  --output reports/acme-security-audit.html

# Generate with custom modifications
prismatic report \
  --scan data/scans/2024-01-15-140000 \
  --modifications fixes.yaml \
  --format html,pdf \
  --output reports/acme-audit
```

### Manual Modifications File
```yaml
# fixes.yaml - Applied before report generation
suppress:
  - finding_id: "prowler-iam-123"
    reason: "False positive - service account"
  
  - finding_id: "trivy-cve-456"
    reason: "Accepted risk - legacy system"

severity_changes:
  - finding_id: "nuclei-789"
    new_severity: "low"
    reason: "Internal only endpoint"

add_notes:
  - finding_id: "kubescape-abc"
    note: "Scheduled for fix in Q2 2024"
```

### Report Structure

#### Executive Summary
- Total findings by severity (Very High, High, Medium, Low)
- Compliance scores by framework
- Top 10 critical risks with brief descriptions
- Scan coverage summary

#### Detailed Findings (by category)
1. **AWS Infrastructure**
   - Grouped by service (IAM, S3, EC2, etc.)
   - Sorted by severity within each service

2. **Container Security**
   - Grouped by image
   - Vulnerability details with fix versions

3. **Kubernetes Security**
   - Grouped by cluster/namespace
   - Configuration issues and vulnerabilities

4. **Web Endpoints**
   - Grouped by domain
   - OWASP categorization

5. **Secrets & Credentials**
   - Grouped by repository/location
   - Sanitized display of findings

### Report Styling - "Professional Prismatic"

```css
/* Theme: Light refraction through precision optics */

:root {
  /* Prismatic gradient - subtle spectrum */
  --prism-gradient: linear-gradient(135deg, 
    rgba(110, 90, 255, 0.1) 0%,
    rgba(100, 170, 255, 0.1) 20%,
    rgba(90, 220, 220, 0.1) 40%,
    rgba(90, 255, 170, 0.1) 60%,
    rgba(220, 255, 90, 0.1) 80%,
    rgba(255, 170, 90, 0.1) 100%
  );
  
  /* Severity colors - gemstone inspired */
  --severity-critical: #9b111e;  /* Ruby */
  --severity-high: #ff6700;      /* Amber */
  --severity-medium: #ffd700;    /* Gold */
  --severity-low: #4169e1;       /* Sapphire */
  --severity-info: #708090;      /* Slate */
  
  /* UI colors - clean, scientific */
  --bg-primary: #fafafa;
  --bg-secondary: #ffffff;
  --text-primary: #1a1a1a;
  --text-secondary: #4a4a4a;
  --border-light: #e0e0e0;
  --accent: #6a5acd;  /* Slate blue */
}

body {
  font-family: 'Inter', -apple-system, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.6;
}

.prismatic-header {
  position: relative;
  padding: 60px 40px;
  background: var(--bg-secondary);
  overflow: hidden;
}

.prismatic-header::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--prism-gradient);
  opacity: 0.4;
  transform: skewY(-2deg);
}

.finding-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-light);
  border-radius: 8px;
  padding: 24px;
  margin: 16px 0;
  position: relative;
  transition: all 0.2s ease;
}

.finding-card::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 4px;
  background: currentColor;
  border-radius: 8px 0 0 8px;
}

.severity-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 12px;
  border-radius: 16px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.severity-critical {
  color: var(--severity-critical);
  background: rgba(155, 17, 30, 0.1);
}

/* Glass morphism for summary cards */
.summary-card {
  background: rgba(255, 255, 255, 0.7);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 16px;
  padding: 24px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.06);
}

/* Subtle prismatic effect on key elements */
.prismatic-accent {
  position: relative;
  background: var(--prism-gradient);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  font-weight: 700;
}
```

## Data Models

### Finding Enrichment
```go
type EnrichedFinding struct {
    Finding
    BusinessContext struct {
        Owner              string   `json:"owner"`
        DataClassification string   `json:"data_classification"`
        ComplianceImpact   []string `json:"compliance_impact"`
        BusinessImpact     string   `json:"business_impact"`
    } `json:"business_context,omitempty"`
    
    RemediationDetails struct {
        Effort       string `json:"effort"` // low, medium, high
        AutoFixable  bool   `json:"auto_fixable"`
        TicketURL    string `json:"ticket_url,omitempty"`
    } `json:"remediation_details,omitempty"`
}
```

## Testing Strategy

### Unit Tests
- Scanner output parsing
- Finding normalization
- Suppression logic
- Severity override logic
- Report generation

### Integration Tests
```go
// tests/integration/scanner_test.go
func TestScannerIntegration(t *testing.T) {
    tests := []struct {
        name     string
        scanner  string
        fixture  string  // Sample output
        expected int     // Expected findings count
    }{
        {"Prowler AWS", "prowler", "testdata/prowler-output.json", 15},
        {"Trivy Container", "trivy", "testdata/trivy-output.json", 8},
        {"Kubescape K8s", "kubescape", "testdata/kubescape-output.json", 12},
    }
    // ...
}
```

### Mock Scanner Mode
```bash
# Use mock data for development/testing
prismatic scan --mock --config configs/test.yaml

# Generates realistic fake findings without running actual scanners
```

### Test Fixtures
```
tests/
??? fixtures/
?   ??? prowler-sample.json
?   ??? trivy-sample.json
?   ??? ...
??? configs/
?   ??? minimal.yaml
?   ??? full-featured.yaml
?   ??? suppression-heavy.yaml
??? expected/
    ??? report-minimal.html
    ??? report-full.html
```

## Error Handling

### Scanner Failures
- Continue scanning with other tools if one fails
- Record failure in metadata
- Show warning in report

### Authentication Errors
```go
// Fail fast with clear messages
if !awsCredsValid() {
    log.Fatal("AWS credentials not found. Please run 'aws configure' or set AWS_PROFILE")
}

if !k8sContextExists(context) {
    log.Fatalf("Kubernetes context '%s' not found. Available contexts: %v", 
        context, getAvailableContexts())
}
```

## Performance Considerations

### Parallel Scanning
```go
// Run scanners in parallel with configurable concurrency
type ScanResult struct {
    Scanner string
    Result  *FindingSet
    Error   error
}

results := make(chan ScanResult, len(scanners))
var wg sync.WaitGroup

for _, scanner := range scanners {
    wg.Add(1)
    go func(s Scanner) {
        defer wg.Done()
        result, err := s.Scan(ctx)
        results <- ScanResult{s.Name(), result, err}
    }(scanner)
}
```

### Resource Limits
- Default timeout: 5 minutes per scanner
- Memory limit: Track large finding sets
- Disk usage: Rotate old scan results

## CLI Design

### Commands
```bash
# Main commands
prismatic scan    # Run security scans
prismatic report  # Generate report from scan data
prismatic list    # List previous scans
prismatic config  # Validate configuration

# Examples
prismatic scan --config client-acme.yaml --only aws,docker
prismatic report --scan latest --format pdf
prismatic list --client acme --limit 10
prismatic config validate --config client-acme.yaml
```

### Output Examples
```
$ prismatic scan --config configs/client-acme.yaml
?? Prismatic Security Scanner v1.0.0
?? Configuration: client-acme.yaml
?? Output: data/scans/2024-01-15-140000

[1/6] ?? Running Prowler (AWS)...
      ? 127 checks completed across 2 regions
      ??  15 findings (2 critical, 5 high, 8 medium)

[2/6] ?? Running Trivy (Containers)...
      ? 3 images scanned
      ??  23 vulnerabilities found (1 critical, 7 high)

[3/6] ?? Running Kubescape (Kubernetes)...
      ? 2 clusters analyzed
      ??  18 security issues detected

[4/6] ?? Running Nuclei (Web Endpoints)...
      ? 3 endpoints tested
      ? No critical vulnerabilities found

[5/6] ?? Running Gitleaks (Secrets)...
      ? Repository scanned
      ? No secrets detected

[6/6] ?? Running Checkov (IaC)...
      ? 15 Terraform files analyzed
      ??  8 misconfigurations found

?? Scan Summary:
   Total Findings: 64
   Critical: 3 | High: 12 | Medium: 31 | Low: 18
   
? Scan complete! Results saved to: data/scans/2024-01-15-140000
?? Run 'prismatic report --scan latest' to generate report
```

## Implementation Notes

### Scanner Integration Pattern
```go
// Standard pattern for each scanner
type ProwlerScanner struct {
    profile string
    regions []string
}

func (s *ProwlerScanner) Scan(ctx context.Context) (*ScanResult, error) {
    cmd := exec.CommandContext(ctx, "prowler",
        "--profile", s.profile,
        "--region", strings.Join(s.regions, ","),
        "--output-formats", "json",
        "--no-banner",
        "--quiet")
    
    output, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("prowler execution failed: %w", err)
    }
    
    findings, err := s.ParseResults(output)
    return &ScanResult{
        Scanner:   "prowler",
        Version:   s.getVersion(),
        StartTime: start,
        EndTime:   time.Now(),
        RawOutput: output,
        Findings:  findings,
    }, nil
}
```

### Development Workflow
1. Start with `scan` command and 1-2 scanners
2. Get basic finding normalization working
3. Implement YAML config and suppressions
4. Add `report` command with simple HTML
5. Iterate on report styling
6. Add remaining scanners
7. Implement PDF generation
8. Polish CLI output and error messages

## Future Enhancements

These features are intentionally deferred to keep the MVP focused:

### Historical Trending
- Track findings across scans to show:
  - First seen / last seen dates
  - Occurrence frequency
  - Risk trend visualization
- Implementation approach: SQLite database for finding history

### Automated Remediation
- Generate fix scripts for common issues:
  - Terraform code for AWS misconfigurations
  - Dockerfile updates for vulnerabilities
  - Kubernetes manifests for security policies
- Safety considerations: Always require manual review

### Additional Integrations
- Jira/GitHub issue creation
- Slack notifications for critical findings
- CI/CD pipeline integration
- Custom scanner plugins

This architecture provides a solid foundation for prismatic while keeping complexity manageable for a solo developer. The two-phase design gives you the flexibility you wanted, and the HTML-first approach ensures Claude Code can help throughout development.
