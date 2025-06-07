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
make lint           # Run linter (uses scripts/fix.sh)
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