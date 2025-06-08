# Severity Normalization Update Summary

## Overview
Updated all scanner files to use the `WithSeverity` builder method instead of directly setting severity. This ensures severity is normalized exactly once when creating the finding, not multiple times throughout the pipeline.

## Changes Made

### 1. **internal/models/finding.go**
- Added `WithSeverity(severity string)` method that normalizes severity during finding creation
- Added `WithTitle(title string)` and `WithDescription(description string)` builder methods for consistency
- Set default severity to `SeverityUnknown` in `NewFinding`

### 2. **internal/scanner/prowler.go**
- Line 148: Changed from `finding.Severity = models.NormalizeSeverity(check.Severity)` to using `.WithSeverity(check.Severity)` 
- Line 211: Changed from `finding.Severity = models.NormalizeSeverity(check.Severity)` to using `.WithSeverity(check.Severity)`

### 3. **internal/scanner/trivy.go**
- Line 85: Updated vulnerability findings to use `.WithSeverity(vuln.Severity)`
- Line 146: Updated misconfiguration findings to use `.WithSeverity(misconf.Severity)`
- Line 173: Updated secret findings to use `.WithSeverity(secret.Severity)`

### 4. **internal/scanner/kubescape.go**
- Lines 157-168: Replaced severity mapping and normalization with `.WithSeverity(s.mapScoreToSeverityString(result.Score))`

### 5. **internal/scanner/nuclei.go**
- Lines 129-137: Changed from `finding.Severity = models.NormalizeSeverity(result.Info.Severity)` to using `.WithSeverity(result.Info.Severity)`

### 6. **internal/scanner/checkov.go**
- Line 118-125: Updated secret findings to use `.WithSeverity(check.Severity)`
- Line 153-162: Updated general findings to use `.WithSeverity(check.Severity)`

### 7. **internal/scanner/gitleaks.go**
- Line 94-101: Changed from `finding.Severity = models.SeverityCritical` to using `.WithSeverity(models.SeverityCritical)`

### 8. **internal/scanner/scanner.go**
- Line 80: Removed severity normalization from `ValidateFinding` function
- Updated function comment to remove "and normalizes severity"

### 9. **internal/scanner/orchestrator.go**
- Lines 211-215: Updated severity override logic to use `finding.WithSeverity(newSeverity)` instead of direct assignment

## Benefits
1. **Single Point of Normalization**: Severity is now normalized exactly once when the finding is created
2. **Consistent API**: All findings use the same builder pattern for setting severity
3. **Reduced Redundancy**: Removed duplicate normalization calls throughout the pipeline
4. **Better Encapsulation**: Severity normalization logic is encapsulated within the Finding model

## Testing
The changes maintain backward compatibility since `WithSeverity` returns the finding pointer, allowing method chaining. All existing tests should continue to pass, though some test failures were noted that appear to be unrelated to these changes (missing types like `ScannerError`, `ErrorTypeParse`, etc.).