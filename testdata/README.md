# Test Data

This directory contains test fixtures and data files used by the test suite.

## Structure

- `configs/` - Test configuration files
  - `test-modifications.yaml` - Example modifications file for testing report modification features
- `scanner/` - Real scanner output data for parser testing
  - `checkov/` - Actual Checkov scan outputs with all 28 fields per finding
  - `gitleaks/` - Sample secrets and configurations for Gitleaks testing
  - `nuclei/` - Nuclei scan outputs and test targets
  - `trivy/` - Trivy vulnerability scan outputs
- `trivy-test/` - Additional Trivy-specific test cases

## Scanner Test Data

The `scanner/` directory contains **real output from security scanners**, not mock data. This ensures our parsers handle actual scanner output correctly.

### Generating Fresh Test Data

```bash
# Generate all scanner test data
./scripts/test/generate-all-testdata.sh

# Generate specific scanner data
./scripts/test/generate-checkov-testdata.sh
./scripts/test/generate-nuclei-testdata.sh
./scripts/test/generate-trivy-testdata.sh
./scripts/test/generate-gitleaks-testdata.sh
```

### Why Real Output Matters

- **Checkov** outputs 28 fields per finding (we only use ~10)
- **Nuclei** outputs nested JSON with array fields
- **Trivy** has complex nested structures for different scan types
- **Gitleaks** includes git history metadata

Using real output ensures we:
1. Handle all fields gracefully (even ones we don't use)
2. Maintain compatibility when scanners update
3. Test edge cases from actual scans

## Usage

Test files in this directory are not meant for production use. They contain sample data
specifically crafted for testing various edge cases and features.

## Note

When adding new test fixtures:
1. Place them in appropriate subdirectories
2. Use descriptive names that indicate their purpose
3. Document any special properties or test cases they cover
4. For scanner data, always use real scanner output, not handcrafted JSON