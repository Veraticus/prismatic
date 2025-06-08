# Prismatic Code Simplification Guide

## Overview
This document outlines 8 specific areas where the Prismatic codebase can be simplified without losing functionality. Each recommendation includes the current implementation, the proposed simplification, and concrete code examples.

---

## 1. Enriched Findings System - Eliminate Duplication

### Current Problem
The enriched findings feature duplicates the entire report data structure and processing logic, requiring separate fields and methods for regular vs enriched findings.

### Current Implementation
```go
// internal/report/html.go - CURRENT (lines 213-230)
type TemplateData struct {
    // Duplicate fields for regular findings
    AWSFindings        []models.Finding
    ContainerFindings  []models.Finding
    KubernetesFindings []models.Finding
    
    // Duplicate fields for enriched findings
    AWSEnrichedFindings        []models.EnrichedFinding
    ContainerEnrichedFindings  []models.EnrichedFinding
    KubernetesEnrichedFindings []models.EnrichedFinding
    
    UseEnriched bool  // Flag to switch between them
}

// Two nearly identical methods
func (g *HTMLGenerator) prepareRegularData(data *TemplateData) { ... }
func (g *HTMLGenerator) prepareEnrichedData(data *TemplateData) { ... }
```

### Proposed Simplification
```go
// internal/models/finding.go - PROPOSED
// Merge Finding and EnrichedFinding into a single type
type Finding struct {
    // All existing Finding fields...
    ID          string            `json:"id"`
    Scanner     string            `json:"scanner"`
    Severity    string            `json:"severity"`
    Title       string            `json:"title"`
    // ... other fields ...
    
    // Optional business context - empty when not enriched
    BusinessContext *BusinessContext `json:"business_context,omitempty"`
}

// internal/report/html.go - PROPOSED
type TemplateData struct {
    // Single set of fields for all findings
    AWSFindings        []models.Finding
    ContainerFindings  []models.Finding
    KubernetesFindings []models.Finding
    // ... other categories ...
    
    // Remove UseEnriched flag - not needed
}

// Single method to prepare all data
func (g *HTMLGenerator) prepareData(data *TemplateData) {
    activeFindingsBySeverity := make(map[string][]models.Finding)
    
    for _, finding := range g.findings {
        if finding.Suppressed {
            data.TotalSuppressed++
            continue
        }
        
        data.TotalActive++
        activeFindingsBySeverity[finding.Severity] = append(activeFindingsBySeverity[finding.Severity], finding)
        
        // Single switch statement for categorization
        switch finding.Scanner {
        case "prowler", "mock-prowler":
            data.AWSFindings = append(data.AWSFindings, finding)
        // ... other cases ...
        }
    }
    // ... rest of method ...
}
```

### Implementation Steps
1. Add `BusinessContext` pointer field to `Finding` struct
2. Remove `EnrichedFinding` type entirely
3. Update orchestrator's `EnrichFindings` to modify findings in-place
4. Remove duplicate fields from `TemplateData`
5. Merge `prepareRegularData` and `prepareEnrichedData` into single method
6. Update templates to check `if .BusinessContext` instead of `if .UseEnriched`

---

## 2. Scanner Type Detection - Remove Unnecessary Abstraction

### Current Problem
The `ScannerTypeDetector` is an over-engineered struct that just checks if configuration arrays are empty.

### Current Implementation
```go
// internal/scanner/factory.go - CURRENT (lines 127-178)
type ScannerTypeDetector struct {
    hasAWS        bool
    hasDocker     bool
    hasKubernetes bool
    hasEndpoints  bool
}

func NewScannerTypeDetector(cfg ClientConfig) *ScannerTypeDetector {
    profiles, _, _ := cfg.GetAWSConfig()
    contexts, _ := cfg.GetKubernetesConfig()
    
    return &ScannerTypeDetector{
        hasAWS:        len(profiles) > 0,
        hasDocker:     len(cfg.GetDockerTargets()) > 0,
        hasKubernetes: len(contexts) > 0,
        hasEndpoints:  len(cfg.GetEndpoints()) > 0,
    }
}

func (d *ScannerTypeDetector) DetectScanners(onlyScanners []string) []string {
    // ... detection logic ...
}
```

### Proposed Simplification
```go
// internal/scanner/orchestrator.go - PROPOSED
// Replace the entire ScannerTypeDetector with a simple function
func (o *Orchestrator) detectScanners(onlyScanners []string) []string {
    // If specific scanners requested, use only those
    if len(onlyScanners) > 0 {
        return onlyScanners
    }
    
    // Otherwise, determine based on configuration
    var scanners []string
    
    // Check AWS config
    if profiles, _, _ := o.GetAWSConfig(); len(profiles) > 0 {
        scanners = append(scanners, "prowler")
    }
    
    // Check Docker config
    if targets := o.GetDockerTargets(); len(targets) > 0 {
        scanners = append(scanners, "trivy")
    }
    
    // Check Kubernetes config
    if contexts, _ := o.GetKubernetesConfig(); len(contexts) > 0 {
        scanners = append(scanners, "kubescape")
    }
    
    // Check endpoints
    if endpoints := o.GetEndpoints(); len(endpoints) > 0 {
        scanners = append(scanners, "nuclei")
    }
    
    // Always include these scanners if not filtered
    scanners = append(scanners, "gitleaks", "checkov")
    
    return scanners
}

// Update InitializeScanners to use the simple function
func (o *Orchestrator) InitializeScanners(onlyScanners []string) error {
    factory := NewScannerFactoryWithLogger(baseConfig, o, o.outputDir, o.useMock, o.logger)
    
    // Direct function call instead of creating detector
    scannerTypes := o.detectScanners(onlyScanners)
    
    // ... rest of method unchanged ...
}
```

### Implementation Steps
1. Delete `ScannerTypeDetector` struct and all its methods
2. Add `detectScanners` method to `Orchestrator`
3. Update `InitializeScanners` to call the new method directly
4. Remove `NewScannerTypeDetector` calls

---

## 3. NDJSON Parsing - Create Common Utility

### Current Problem
Multiple scanners implement their own newline-delimited JSON parsing with identical logic.

### Current Implementation
```go
// internal/scanner/prowler.go - CURRENT (lines 242-258)
func (s *ProwlerScanner) parseNDJSONOCSF(raw []byte) []ProwlerOCSFCheck {
    var results []ProwlerOCSFCheck
    lines := strings.Split(string(raw), "\n")
    
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        
        var item ProwlerOCSFCheck
        if err := json.Unmarshal([]byte(line), &item); err == nil {
            results = append(results, item)
        }
    }
    
    return results
}

// Similar duplicated logic in parseNDJSONNative and Nuclei scanner
```

### Proposed Simplification
```go
// internal/scanner/parser.go - NEW FILE
package scanner

import (
    "encoding/json"
    "strings"
)

// ParseNDJSON parses newline-delimited JSON into a slice of the specified type.
// Usage: 
//   var checks []ProwlerOCSFCheck
//   err := ParseNDJSON(raw, &checks)
func ParseNDJSON[T any](raw []byte, result *[]T) error {
    lines := strings.Split(string(raw), "\n")
    
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        
        var item T
        if err := json.Unmarshal([]byte(line), &item); err == nil {
            *result = append(*result, item)
        }
        // Silently skip malformed lines like the original code
    }
    
    return nil
}

// internal/scanner/prowler.go - PROPOSED
func (s *ProwlerScanner) parseOCSFFormat(raw []byte) ([]models.Finding, error) {
    var checks []ProwlerOCSFCheck
    
    // Try parsing as JSON array first
    if err := json.Unmarshal(raw, &checks); err != nil {
        // Fall back to NDJSON parsing
        if err := ParseNDJSON(raw, &checks); err != nil {
            return nil, NewScannerError(s.Name(), "parse", err)
        }
    }
    
    // ... rest of method unchanged ...
}

// internal/scanner/nuclei.go - PROPOSED
func (s *NucleiScanner) ParseResults(raw []byte) ([]models.Finding, error) {
    var results []nucleiResult
    
    // Use the common NDJSON parser
    if err := ParseNDJSON(raw, &results); err != nil {
        return nil, err
    }
    
    var findings []models.Finding
    for _, result := range results {
        finding := s.resultToFinding(result)
        if err := finding.IsValid(); err == nil {
            findings = append(findings, *finding)
        }
    }
    
    return findings, nil
}
```

### Implementation Steps
1. Create new file `internal/scanner/parser.go`
2. Implement generic `ParseNDJSON` function
3. Replace `parseNDJSONOCSF` and `parseNDJSONNative` with calls to `ParseNDJSON`
4. Update Nuclei scanner to use `ParseNDJSON`
5. Remove duplicate parsing methods

---

## 4. Modifications System - Simplify Structure

### Current Problem
The modifications system has unnecessary metadata fields that add complexity without providing real value.

### Current Implementation
```go
// internal/report/modifications.go - CURRENT (lines 26-41)
type Suppression struct {
    FindingID    string     `yaml:"finding_id"`
    Reason       string     `yaml:"reason"`
    SuppressedAt time.Time  `yaml:"suppressed_at"`      // Unnecessary
    SuppressedBy string     `yaml:"suppressed_by"`      // Rarely useful
    ExpiresAt    *time.Time `yaml:"expires_at,omitempty"` // Adds complexity
}

type SeverityOverride struct {
    FindingID    string    `yaml:"finding_id"`
    NewSeverity  string    `yaml:"new_severity"`
    Reason       string    `yaml:"reason"`
    OverriddenAt time.Time `yaml:"overridden_at"`  // Unnecessary
    OverriddenBy string    `yaml:"overridden_by"`  // Rarely useful
}
```

### Proposed Simplification
```go
// internal/report/modifications.go - PROPOSED
type Modifications struct {
    // Remove Version field - not needed
    LastModified time.Time              `yaml:"last_modified"`
    Author       string                 `yaml:"author,omitempty"`
    Description  string                 `yaml:"description,omitempty"`
    Suppressions map[string]string      `yaml:"suppressions"`      // finding_id -> reason
    Overrides    map[string]Override    `yaml:"overrides"`         // finding_id -> override
    Comments     map[string]string      `yaml:"comments,omitempty"`
}

type Override struct {
    NewSeverity string `yaml:"new_severity"`
    Reason      string `yaml:"reason"`
}

// Simplified apply method
func (m *Modifications) ApplyModifications(findings []models.Finding) []models.Finding {
    modified := make([]models.Finding, len(findings))
    
    for i, finding := range findings {
        modified[i] = finding
        
        // Check suppression - much simpler lookup
        if reason, exists := m.Suppressions[finding.ID]; exists {
            modified[i].Suppressed = true
            modified[i].SuppressionReason = reason
        }
        
        // Check severity override - cleaner structure
        if override, exists := m.Overrides[finding.ID]; exists {
            modified[i].OriginalSeverity = finding.Severity
            modified[i].Severity = override.NewSeverity
            // Optionally add reason to metadata
            if override.Reason != "" {
                modified[i].Metadata["override_reason"] = override.Reason
            }
        }
        
        // Add comment if exists
        if comment, exists := m.Comments[finding.ID]; exists {
            modified[i].Comment = comment
        }
    }
    
    return modified
}

// Simplified example
func Example() *Modifications {
    return &Modifications{
        LastModified: time.Now(),
        Author:       "security-team@example.com",
        Description:  "Q4 2024 security scan modifications",
        Suppressions: map[string]string{
            "abc123def456": "False positive - S3 bucket is intentionally public for static website",
            "ghi789jkl012": "Accepted risk - legacy system scheduled for decommission Q1 2025",
        },
        Overrides: map[string]Override{
            "mno345pqr678": {
                NewSeverity: "low",
                Reason:      "Mitigating controls in place",
            },
        },
        Comments: map[string]string{
            "stu901vwx234": "Tracking in JIRA ticket SEC-1234",
        },
    }
}
```

### Implementation Steps
1. Simplify `Suppression` to just a map of finding_id -> reason
2. Simplify `SeverityOverride` to minimal `Override` struct
3. Remove Version field and validation
4. Update `ApplyModifications` to use map lookups
5. Update example generation
6. Update YAML parsing/saving logic

---

## 5. Error Handling - Use Standard Go Patterns

### Current Problem
Custom error types with multiple abstraction layers add complexity without providing significant value over standard Go error wrapping.

### Current Implementation
```go
// internal/scanner/errors.go - CURRENT
type ScannerError struct {
    Scanner   string
    Type      ErrorType
    Message   string
    Err       error
    Retryable bool
}

func NewStructuredError(scanner string, errType ErrorType, err error) *ScannerError {
    return &ScannerError{
        Scanner:   scanner,
        Type:      errType,
        Message:   err.Error(),
        Err:       err,
        Retryable: isRetryable(errType),
    }
}

// Usage is inconsistent across scanners
```

### Proposed Simplification
```go
// internal/scanner/errors.go - PROPOSED (or just DELETE this file)
// Use standard Go error wrapping instead

// internal/scanner/prowler.go - PROPOSED
func (s *ProwlerScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
    // ... scanner logic ...
    
    output, err := cmd.CombinedOutput()
    if err != nil {
        // Simple, clear error wrapping
        return nil, fmt.Errorf("prowler scan failed for profile %s: %w", profile, err)
    }
    
    findings, err := s.ParseResults(output)
    if err != nil {
        // Context-specific error messages
        return nil, fmt.Errorf("parsing prowler results: %w", err)
    }
    
    return result, nil
}

// For cases where retry logic is needed, use a simple function
func isRetryableError(err error) bool {
    // Check for specific error conditions
    if errors.Is(err, context.DeadlineExceeded) {
        return true
    }
    
    // Check error strings for network issues
    errStr := err.Error()
    return strings.Contains(errStr, "connection refused") ||
           strings.Contains(errStr, "timeout") ||
           strings.Contains(errStr, "temporary failure")
}

// In orchestrator, if retry is needed
if err != nil && isRetryableError(err) {
    // Retry logic here
}
```

### Implementation Steps
1. Delete `errors.go` file entirely
2. Replace all `NewScannerError` calls with `fmt.Errorf`
3. Add scanner name to error messages where needed
4. Create simple `isRetryableError` helper if retry logic is needed
5. Update error handling in orchestrator to use standard errors

---

## 6. Mock Scanner Factory - Separate Concerns

### Current Problem
Mock scanner logic is intertwined with the real scanner factory, requiring a check on every scanner creation.

### Current Implementation
```go
// internal/scanner/factory.go - CURRENT (line 44-47)
func (f *ScannerFactory) CreateScanner(scannerType string) (Scanner, error) {
    if f.useMock {
        return NewMockScannerWithLogger(scannerType, f.config, f.logger), nil
    }
    // ... real scanner creation ...
}
```

### Proposed Simplification
```go
// internal/scanner/factory.go - PROPOSED
// Remove useMock field from ScannerFactory
type ScannerFactory struct {
    config    Config
    clientCfg ClientConfig
    outputDir string
    logger    logger.Logger
    // Remove: useMock bool
}

// internal/scanner/mock_factory.go - NEW FILE
package scanner

type MockScannerFactory struct {
    config Config
    logger logger.Logger
}

func NewMockScannerFactory(config Config, log logger.Logger) *MockScannerFactory {
    return &MockScannerFactory{
        config: config,
        logger: log,
    }
}

func (f *MockScannerFactory) CreateScanner(scannerType string) (Scanner, error) {
    return NewMockScannerWithLogger(scannerType, f.config, f.logger), nil
}

// internal/scanner/orchestrator.go - PROPOSED
func (o *Orchestrator) InitializeScanners(onlyScanners []string) error {
    baseConfig := Config{
        WorkingDir: o.outputDir,
        Timeout:    300,
        Debug:      false,
    }
    
    // Create appropriate factory based on mock flag
    var factory interface {
        CreateScanner(string) (Scanner, error)
    }
    
    if o.useMock {
        factory = NewMockScannerFactory(baseConfig, o.logger)
    } else {
        factory = NewScannerFactoryWithLogger(baseConfig, o, o.outputDir, o.logger)
    }
    
    // ... rest of method unchanged ...
}
```

### Implementation Steps
1. Create new file `internal/scanner/mock_factory.go`
2. Move mock-specific logic to `MockScannerFactory`
3. Remove `useMock` field from `ScannerFactory`
4. Update `InitializeScanners` to choose factory type
5. Define common interface for factories if needed

---

## 7. Severity Normalization - Centralize Logic

### Current Problem
Severity normalization is scattered across multiple places, leading to potential inconsistencies.

### Current Implementation
```go
// Currently happens in:
// 1. Each scanner's ParseResults method
// 2. ValidateFinding function
// 3. Orchestrator's processResult method
// 4. NormalizeSeverity is called multiple times
```

### Proposed Simplification
```go
// internal/models/finding.go - PROPOSED
// Always normalize severity in the constructor
func NewFinding(scanner, findingType, resource, location string) *Finding {
    return &Finding{
        ID:             GenerateFindingID(scanner, findingType, resource, location),
        Scanner:        scanner,
        Type:           findingType,
        Resource:       resource,
        Location:       location,
        Metadata:       make(map[string]string),
        DiscoveredDate: time.Now(),
        // Set a default that will be overridden
        Severity:       SeverityUnknown,
    }
}

// Add a builder method for setting severity
func (f *Finding) WithSeverity(severity string) *Finding {
    // ALWAYS normalize when setting severity
    f.Severity = NormalizeSeverity(severity)
    return f
}

// internal/scanner/prowler.go - PROPOSED
func (s *ProwlerScanner) parseOCSFFormat(raw []byte) ([]models.Finding, error) {
    // ... parsing logic ...
    
    finding := models.NewFinding(s.Name(), check.Finding.Type, resource, location).
        WithSeverity(check.Severity).  // Automatically normalized
        WithTitle(check.Finding.Title).
        WithDescription(check.Finding.Desc)
    
    // No need to call NormalizeSeverity again
    findings = append(findings, *finding)
}

// internal/scanner/scanner.go - PROPOSED
// Simplify ValidateFinding - no need to normalize here
func ValidateFinding(f *models.Finding) error {
    if err := f.IsValid(); err != nil {
        return fmt.Errorf("invalid finding: %w", err)
    }
    
    // Remove severity normalization - already done in WithSeverity
    
    // Generate ID if not set
    if f.ID == "" {
        f.ID = models.GenerateFindingID(f.Scanner, f.Type, f.Resource, f.Location)
    }
    
    return nil
}
```

### Implementation Steps
1. Add `WithSeverity` method to Finding
2. Update all scanners to use `WithSeverity` method
3. Remove `NormalizeSeverity` calls from `ValidateFinding`
4. Remove normalization from orchestrator's `processResult`
5. Ensure severity is normalized exactly once at creation time

---

## 8. HTML Report Categorization - Use Maps

### Current Problem
The HTML report uses repetitive switch statements and manual counting logic that could be simplified with a map-based approach.

### Current Implementation
```go
// internal/report/html.go - CURRENT (lines 266-281)
// Repeated switch statements for categorization
switch finding.Scanner {
case "prowler", "mock-prowler":
    data.AWSFindings = append(data.AWSFindings, finding)
case "trivy", "mock-trivy":
    data.ContainerFindings = append(data.ContainerFindings, finding)
// ... more cases ...
}

// Manual severity counting
data.CriticalCount = len(activeFindingsBySeverity["critical"])
data.HighCount = len(activeFindingsBySeverity["high"])
// ... more manual counting ...
```

### Proposed Simplification
```go
// internal/report/html.go - PROPOSED
// Define scanner categories as a map
var scannerCategories = map[string]string{
    "prowler":       "aws",
    "mock-prowler":  "aws",
    "trivy":         "container",
    "mock-trivy":    "container",
    "kubescape":     "kubernetes",
    "mock-kubescape": "kubernetes",
    "nuclei":        "web",
    "mock-nuclei":   "web",
    "gitleaks":      "secrets",
    "mock-gitleaks": "secrets",
    "checkov":       "iac",
    "mock-checkov":  "iac",
}

type TemplateData struct {
    // Use a map for findings by category
    FindingsByCategory map[string][]models.Finding
    
    // Use a map for severity counts
    SeverityCounts map[string]int
    
    // Other fields remain the same
    TotalActive     int
    TotalSuppressed int
    // ...
}

func (g *HTMLGenerator) prepareData(data *TemplateData) {
    data.FindingsByCategory = make(map[string][]models.Finding)
    data.SeverityCounts = make(map[string]int)
    
    activeFindingsBySeverity := make(map[string][]models.Finding)
    
    for _, finding := range g.findings {
        if finding.Suppressed {
            data.TotalSuppressed++
            continue
        }
        
        data.TotalActive++
        
        // Automatic severity counting
        data.SeverityCounts[finding.Severity]++
        activeFindingsBySeverity[finding.Severity] = append(activeFindingsBySeverity[finding.Severity], finding)
        
        // Automatic categorization using map
        if category, exists := scannerCategories[finding.Scanner]; exists {
            data.FindingsByCategory[category] = append(data.FindingsByCategory[category], finding)
        }
    }
    
    // Sort each category
    for category := range data.FindingsByCategory {
        sortFindings(data.FindingsByCategory[category])
    }
    
    // ... rest of method ...
}

// Update template to iterate over map
// {{range $category, $findings := .FindingsByCategory}}
//   <h3>{{$category | title}} Security</h3>
//   {{range $findings}}
//     <!-- finding card -->
//   {{end}}
// {{end}}
```

### Implementation Steps
1. Define `scannerCategories` map at package level
2. Change `TemplateData` to use maps instead of individual fields
3. Update `prepareData` to use map-based categorization
4. Update HTML template to iterate over the map
5. Remove duplicate sorting calls

---

## Implementation Priority

1. **Error Handling** (easiest, touches many files)
2. **Scanner Type Detection** (localized change)
3. **NDJSON Parsing** (creates reusable utility)
4. **Modifications System** (self-contained)
5. **Mock Scanner Factory** (clean separation)
6. **Severity Normalization** (touches all scanners)
7. **HTML Report Categorization** (requires template updates)
8. **Enriched Findings** (most complex, touches core data model)

Each simplification can be implemented independently, allowing for incremental improvements to the codebase.