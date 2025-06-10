# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Building
```bash
make build          # Build the binary
make build-all      # Build for all platforms (Linux and Darwin)
```

### Testing
```bash
make test           # Run tests
make test-race      # Run tests with race detection
make test-coverage  # Run tests with coverage
make test-all       # Run comprehensive tests (all checks and cross-platform builds)
make quick          # Quick format and test for development
```

### Code Quality
```bash
make fix            # Auto-fix formatting and common issues
make lint           # Run linter - MUST PASS with 0 issues
make fmt            # Format code with gofmt
make vet            # Run go vet
```

### Development Workflow
```bash
make check          # Run fmt, vet, and test
make run ARGS=...   # Build and run the application with arguments
make cover          # Generate coverage report with HTML output
```

## Architecture

Prismatic is a security scanning orchestrator designed to combine multiple open-source security tools into unified reports. Key architectural elements:

### Two-Phase Operation
1. **Scanning Phase** (`prismatic scan`): Runs security scanners and stores normalized results
2. **Report Phase** (`prismatic report`): Generates beautiful HTML/PDF reports from scan data

### Scanner Integration Pattern
- Each scanner implements a common `Scanner` interface
- Scanners produce normalized `Finding` objects with stable IDs
- Findings can be suppressed via YAML configuration
- Raw scanner output is preserved for debugging

### Key Components
- **cmd/** - CLI commands (scan and report)
- **internal/scanner/** - Scanner integrations (Prowler, Trivy, Kubescape, Nuclei, Gitleaks, Checkov)
- **internal/models/** - Core data structures
- **internal/config/** - YAML configuration handling
- **internal/report/** - HTML/PDF report generation
- **configs/** - Client-specific YAML configurations
- **data/scans/** - Scan results storage

### Client Configuration
Prismatic uses YAML files to configure scanning per client/environment, including:
- AWS regions and profiles
- Docker registries and containers
- Kubernetes contexts and namespaces
- Web endpoints to scan
- Finding suppressions and severity overrides
- Business context metadata

### Report Design
Reports are optimized for AI readability with:
- Professional "prismatic" theming using light refraction metaphors
- Severity-based color coding (gemstone-inspired)
- Glass morphism effects on summary cards
- Findings grouped by category and service

## Development Notes

- The project is in early development (initial commit stage)
- Focus on HTML-first reporting for Claude Code compatibility
- Two-phase design allows manual review between scanning and reporting
- Finding IDs are deterministic hashes for reliable suppression tracking

## Critical Development Requirements

**IMPORTANT**: ALL tests and linters MUST pass before any changes are considered complete. This is non-negotiable for CI/CD pipeline success.

**IMPORTANT**: Do NOT commit changes. The user will handle all git commits. Focus on making the changes and ensuring they work correctly.

### Before Committing Any Changes:

1. **Run all tests**: `make test`
   - ALL unit tests must pass
   - Integration tests may be skipped with `-short` flag if tools aren't installed
   
2. **Run linters**: `make lint`
   - ALL linter issues must be fixed
   - No warnings or errors should remain
   - This includes:
     - `golangci-lint` checks
     - `gofmt` formatting
     - `go vet` analysis
     - Security checks (`gosec`)
     - Style checks (`revive`)
     - Static analysis (`staticcheck`)

3. **Verify build**: `make build`
   - The project must compile without errors

### Quick Verification Command:
```bash
# Run this before considering any work complete:
make lint && make test && make build
```

If ANY of these commands fail, the work is not complete. Fix all issues before proceeding.