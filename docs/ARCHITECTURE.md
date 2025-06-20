# Prismatic Architecture

## Overview

Prismatic is a unified security scanning platform that combines multiple open-source security tools into a single, elegant TUI (Terminal User Interface) application. Built on modern Go with a SQLite backend, it provides real-time security scanning for containers, Kubernetes, infrastructure-as-code, and web applications.

## Core Principles

1. **Single Entry Point**: One command (`prismatic`) launches an interactive TUI
2. **Native Go Integration**: All scanners use native Go libraries - no exec() calls
3. **Database-Centric**: SQLite provides persistent storage and enables rich queries
4. **User-First Design**: Beautiful TUI with intuitive navigation and real-time feedback
5. **Testable Architecture**: Interfaces, dependency injection, and in-memory databases for testing
6. **Progressive Enhancement**: Start simple, add features without breaking changes

## Architecture Decisions

### 1. Terminal User Interface (TUI)

Prismatic uses a TUI-first approach inspired by tools like k9s, lazygit, and btop:

```
┌─────────────────────────────────────────┐
│          Prismatic Security Scanner      │
│  ┌─────────┬────────────┬───────────┐  │
│  │ Scanner │  Findings   │  Reports  │  │
│  │ Config  │   Display   │ Generator │  │
│  └─────────┴────────────┴───────────┘  │
│                                         │
│  [n]ew [h]istory [q]uit                │
└─────────────────────────────────────────┘
```

**Key Decisions:**
- Built with bubbletea/lipgloss for modern TUI capabilities
- Vim-style (hjkl) and arrow key navigation
- Split panes for main content, modals for important actions
- Color-coded severity levels:
  - Critical = Red
  - High = Orange  
  - Medium = Yellow
  - Low = Blue
  - Info = Gray

### 2. Data Storage

All operational data lives in a single SQLite database (`prismatic.db`):

```sql
-- Core schema
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aws_profile TEXT,
    aws_regions TEXT, -- JSON array
    kube_context TEXT,
    scanners INTEGER, -- Bitmask of enabled scanners
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT CHECK(status IN ('running', 'completed', 'failed')),
    error_details TEXT
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    scanner TEXT,
    severity TEXT CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    title TEXT,
    description TEXT,
    resource TEXT,
    technical_details JSON, -- Scanner-specific structured data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_findings_scan (scan_id),
    INDEX idx_findings_severity (severity)
);

CREATE TABLE suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER REFERENCES findings(id),
    reason TEXT,
    suppressed_by TEXT, -- Username or "system"
    suppressed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_suppressions_finding (finding_id)
);
```

**Key Decisions:**
- Single file database in working directory
- No multi-tenancy - one database per user
- Bitmask for efficient scanner configuration storage
- JSON fields for flexible scanner-specific data
- Indexes on commonly queried fields

### 3. Scanner Architecture

All scanners implement a common interface using native Go libraries:

```go
type Scanner interface {
    // Metadata
    Name() string
    Description() string
    
    // Configuration
    ValidateConfig(ctx context.Context) error
    
    // Execution - returns channel for streaming results
    Scan(ctx context.Context, targets ScanTargets) (<-chan Finding, error)
}

type ScanTargets struct {
    AWSProfile   string
    AWSRegions   []string
    KubeContext  string
    WebEndpoints []string
    GitRepos     []string
    // Scanner-specific targets can extend this
}
```

**Supported Scanners (All Native Go):**

| Scanner | Purpose | Go Library |
|---------|---------|------------|
| Trivy | Container & IaC scanning | `github.com/aquasecurity/trivy/pkg/scanner` |
| Nuclei | Web vulnerability scanning | `github.com/projectdiscovery/nuclei/v3/lib` |
| Gitleaks | Secret detection | `github.com/zricethezav/gitleaks/v8/detect` |
| Kubeaudit | Kubernetes security | Direct library usage |
| tfsec | Terraform security | Direct library usage |
| Terrascan | Multi-IaC scanning | Direct library usage |

**Scanner Storage:**
```go
type ScannerFlag uint32

const (
    ScannerTrivy ScannerFlag = 1 << iota
    ScannerNuclei
    ScannerGitleaks
    ScannerKubeaudit
    ScannerTfsec
    ScannerTerrascan
)

// Database stores as single integer: 63 = all scanners enabled
```

### 4. Finding Model

Findings use a two-stage enrichment model to maximize data richness:

```go
type Finding struct {
    // Core fields (common to all scanners)
    ID          int64
    ScanID      int64
    Scanner     string
    Severity    Severity
    Title       string
    Description string
    Resource    string
    
    // Technical details (populated during scan)
    Technical   TechnicalDetails // Interface for scanner-specific data
    
    // Contextual enrichment (populated in future enrichment phase)
    Contextual  *ContextualEnrichment // Nullable for v1
}

// Scanner-specific implementations
type TrivyTechnical struct {
    CVE          string
    CVSS         CVSSDetails
    Package      string
    Version      string
    FixedVersion string
    References   []string
}

type NucleiTechnical struct {
    TemplateID   string
    TemplatePath string
    Matcher      string
    Evidence     string
    Request      string
    Response     string
}
```

**Key Decisions:**
- Rich, typed scanner-specific data structures
- No loss of information from native libraries
- Prepared for future AI enrichment phase
- Stored as JSON in `technical_details` column

### 5. Execution Model

Parallel scanning with proper resource management:

```go
type ScanOrchestrator struct {
    db          *sql.DB
    scanners    []Scanner
    workerPool  *WorkerPool
    bufferSize  int
}

func (o *ScanOrchestrator) ExecuteScan(ctx context.Context, config ScanConfig) error {
    // Create scan record
    scanID := o.createScan(config)
    
    // Finding buffer for batch writes
    buffer := make([]Finding, 0, o.bufferSize)
    mu := &sync.Mutex{}
    
    // Launch scanners in parallel
    g, ctx := errgroup.WithContext(ctx)
    
    for _, scanner := range o.enabledScanners(config) {
        scanner := scanner
        g.Go(func() error {
            findings, err := scanner.Scan(ctx, config.Targets)
            if err != nil {
                return fmt.Errorf("%s: %w", scanner.Name(), err)
            }
            
            // Stream findings to buffer
            for finding := range findings {
                mu.Lock()
                buffer = append(buffer, finding)
                if len(buffer) >= o.bufferSize {
                    o.flushFindings(scanID, buffer)
                    buffer = buffer[:0]
                }
                mu.Unlock()
            }
            return nil
        })
    }
    
    // Wait for completion and flush remaining
    err := g.Wait()
    o.flushFindings(scanID, buffer)
    o.completeScan(scanID, err)
    return err
}
```

**Key Decisions:**
- Worker pool limits concurrent scanners
- Buffered writes to handle SQLite write locks
- Graceful error handling with partial results
- Context cancellation for clean shutdown

### 6. User Interface Flow

```
Main Menu
    ├─→ New Scan
    │     ├─→ Configure (select scanners, set targets)
    │     ├─→ Start Scan
    │     ├─→ Progress View (with cancel option)
    │     └─→ Results Browser
    │
    ├─→ Scan History
    │     ├─→ View Past Scans
    │     ├─→ Load Results
    │     └─→ Delete Old Scans
    │
    └─→ Results Browser
          ├─→ Finding List (grouped by severity)
          ├─→ Finding Details
          ├─→ Suppression Management
          └─→ Report Generation
```

**Progress Display:**
```
┌─ Scanning ─────────────────────────┐
│ Trivy:      ████████░░ (80%)       │
│ Nuclei:     ██████░░░░ (60%)       │
│ Gitleaks:   ██████████ (Complete)  │
│                                    │
│ Total Findings: 234                │
│ Elapsed: 3m 42s                    │
│                                    │
│ [q] Stop Scan                      │
└────────────────────────────────────┘
```

### 7. Configuration Management

No YAML files - configuration via environment and TUI:

```go
type AppConfig struct {
    // From environment
    AWSProfile   string // AWS_PROFILE or default
    AWSConfig    string // ~/.aws/credentials location
    KubeConfig   string // KUBECONFIG or ~/.kube/config
    KubeContext  string // Current context from kubeconfig
    
    // From TUI interaction
    EnabledScanners ScannerFlag
    ScanTargets     ScanTargets
}

func (c *AppConfig) Validate() error {
    if c.AWSProfile == "" {
        return fmt.Errorf("AWS profile not configured. Set AWS_PROFILE or ensure ~/.aws/credentials exists")
    }
    if c.KubeContext == "" {
        return fmt.Errorf("Kubernetes context not configured. Set KUBECONFIG or ensure ~/.kube/config exists")
    }
    return nil
}
```

### 8. Report Generation

HTML.

```go
type ReportGenerator struct {
    templatePath string
    db           *sql.DB
}

func (r *ReportGenerator) Generate(scanID int64, format ReportFormat) (string, error) {
    // Load findings from database
    findings := r.loadFindings(scanID)
    
    // Group by severity and scanner
    grouped := r.groupFindings(findings)
    
    // Generate HTML
    html := r.renderHTML(grouped)
    
    return r.saveHTML(html)
}
```

**Report Features:**
- Professional "prismatic" design theme
- Severity-based color coding
- Executive summary with metrics
- Detailed findings with remediation
- Suppressed findings appendix

### 9. Testing Strategy

Comprehensive testing approach leveraging interfaces:

```go
// In-memory database for tests
func NewTestDB() *sql.DB {
    db, _ := sql.Open("sqlite3", ":memory:")
    // Run migrations
    return db
}

// Integration test example
func TestScanOrchestrator(t *testing.T) {
    db := NewTestDB()
    
    // Create a real scanner with test configuration
    trivyScanner := trivy.NewScanner(trivy.Config{
        ImageName: "alpine:latest",
    })
    
    orch := NewScanOrchestrator(db, []Scanner{trivyScanner})
    err := orch.ExecuteScan(context.Background(), testConfig)
    
    assert.NoError(t, err)
    // Verify findings in database
}
```

### 10. Error Handling

Multi-error collection for comprehensive feedback:

```go
type ScanErrors struct {
    errors map[string]error
    mu     sync.Mutex
}

func (e *ScanErrors) Add(scanner string, err error) {
    e.mu.Lock()
    defer e.mu.Unlock()
    e.errors[scanner] = err
}

func (e *ScanErrors) Error() string {
    if len(e.errors) == 0 {
        return ""
    }
    
    var parts []string
    for scanner, err := range e.errors {
        parts = append(parts, fmt.Sprintf("%s: %v", scanner, err))
    }
    return strings.Join(parts, "; ")
}
```

### 11. Package Structure

Clean, testable organization:

```
prismatic/
├── cmd/
│   └── prismatic/
│       └── main.go          # Entry point
├── internal/
│   ├── database/
│   │   ├── migrations.go    # Schema setup
│   │   ├── queries.go       # Common queries
│   │   └── db.go           # Database helpers
│   ├── scanner/
│   │   ├── interface.go     # Scanner interface
│   │   ├── orchestrator.go  # Parallel execution
│   │   ├── trivy/          # Scanner implementations
│   │   ├── nuclei/
│   │   ├── gitleaks/
│   │   ├── kubeaudit/
│   │   ├── tfsec/
│   │   └── terrascan/
│   ├── tui/
│   │   ├── app.go          # Main TUI application
│   │   ├── pages/          # Different screens
│   │   ├── components/     # Reusable UI components
│   │   └── styles.go       # Consistent styling
│   ├── models/
│   │   ├── finding.go      # Core data models
│   │   ├── scan.go
│   │   └── severity.go
│   └── report/
│       ├── generator.go    # Report generation
│       ├── templates/      # HTML templates
│       └── assets/         # CSS, images
├── pkg/
│   └── version/           # Version information
└── prismatic.db           # SQLite database (git ignored)
```

## Security Considerations

1. **No Sensitive Data in Logs**: Scanner credentials never logged
2. **Database Security**: Local file with user permissions only
3. **Input Validation**: All user input sanitized before database storage
4. **Credential Management**: Leverages existing AWS/Kube credential chains
5. **No Network Services**: Pure local CLI tool, no attack surface

## Performance Targets

- **Startup Time**: < 1 second to TUI display
- **Scan Initiation**: < 5 seconds from config to first finding
- **Finding Ingestion**: > 1000 findings/second
- **Memory Usage**: < 500MB for 10,000 findings
- **Database Size**: ~100KB per 100 findings

## Future Enhancements (Post-v1)

1. **AI-Powered Enrichment**: Add contextual analysis phase
2. **Scan Profiles**: Save and reuse scanner configurations
3. **AWS Security**: Integrate native AWS security scanning
4. **Real-time Streaming**: Show findings as they're discovered
5. **REST API**: Optional API server for integrations
6. **Cloud Backends**: Support for S3/GCS database storage
7. **Collaborative Features**: Team-based suppression management

## Development Workflow

```bash
# Run the application
go run cmd/prismatic/main.go

# Run tests with coverage
go test -cover ./...

# Run integration tests
go test -tags=integration ./...

# Build for release
go build -o prismatic cmd/prismatic/main.go

# Database debugging
sqlite3 prismatic.db "SELECT COUNT(*) FROM findings"
```

## MVP Success Criteria

1. **Single Command Launch**: `prismatic` starts TUI immediately
2. **Intuitive Navigation**: New users productive in < 5 minutes
3. **Reliable Scanning**: No crashed scans, partial results on error
4. **Beautiful Reports**: Professional PDFs ready for clients
5. **Fast Execution**: Complete scan in < 10 minutes
6. **Zero Configuration**: Works with existing AWS/Kube setup
7. **Comprehensive Coverage**: 6 scanners across all infrastructure

---

This architecture provides a solid foundation for a modern, user-friendly security scanning platform that leverages the best of Go's ecosystem while providing an exceptional user experience through its TUI interface.
