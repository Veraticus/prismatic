# Prismatic Scripts

This directory contains utility scripts for the Prismatic project.

## Security Scanner Installation

### install-scanners.sh

Checks for and helps install the required security scanning tools.

```bash
./scripts/install-scanners.sh
```

**What it does:**
- Detects which scanners are already installed
- Provides OS-specific installation instructions for missing tools
- Verifies additional requirements (Docker, kubectl, AWS CLI)
- Returns exit code 0 if all tools are installed, 1 if any are missing

**Supported scanners:**
- Prowler (AWS security)
- Trivy (container security)
- Kubescape (Kubernetes security)
- Nuclei (web vulnerability scanning)
- Gitleaks (secret detection)
- Checkov (IaC security)

## Development Tools

### install-dev-tools.sh

Installs Go development tools needed for contributing to Prismatic.

```bash
./scripts/install-dev-tools.sh
```

**Tools installed:**
- golangci-lint (meta linter)
- goimports (import formatting)
- misspell (spell checker)
- staticcheck (static analysis)
- gosec (security checker)
- ineffassign (ineffectual assignment checker)
- errcheck (error handling checker)

## Code Quality

### fix.sh

Runs automatic code fixes and formatting.

```bash
./scripts/fix.sh
# or
make fix
```

**What it does:**
1. Formats Go code with `gofmt`
2. Organizes imports with `goimports`
3. Fixes common misspellings
4. Runs golangci-lint auto-fixes

### lint.sh

Runs all linters and reports issues.

```bash
./scripts/lint.sh
# or
make lint
```

## Testing

### test-all.sh

Runs comprehensive test suite across multiple platforms.

```bash
./scripts/test-all.sh
# or
make test-all
```

**Test phases:**
1. Code formatting checks
2. Go vet analysis
3. Linter checks
4. Unit tests
5. Race condition tests
6. Integration tests
7. Cross-platform build verification

### screenshot.sh

Generates a screenshot of an HTML report for documentation.

```bash
./scripts/screenshot.sh <html-file> <output-png>
```

**Example:**
```bash
./scripts/screenshot.sh reports/example.html docs/report-screenshot.png
```

### view-report.sh

Opens an HTML report in your default browser.

```bash
./scripts/view-report.sh <report-file>
# or
prismatic report -c config.yaml --open
```

## Nix Packaging

### update-nix-hashes.sh

Updates all Nix-related hashes in the project to match the current Git HEAD commit.

```bash
./scripts/update-nix-hashes.sh
# or
make update-nix
```

**What it does:**
1. Updates Git revision in `default.nix` and `README.md`
2. Calculates and updates GitHub archive hash
3. Calculates and updates Go vendor dependencies hash

**When to use:**
- After updating Go dependencies
- Before creating a release
- When updating Nix packaging

## Usage Tips

1. **Make targets**: Most scripts have corresponding make targets for convenience
2. **Exit codes**: Scripts use standard exit codes (0 for success, non-zero for failure)
3. **Help**: Run scripts with `-h` or `--help` for usage information
4. **Colors**: Scripts use colored output when running in a terminal
5. **CI/CD**: Scripts detect CI environments and adjust output accordingly