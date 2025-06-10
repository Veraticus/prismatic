# Prismatic Enrichment Feature Design

## Overview

The enrichment feature adds AI-powered analysis to security findings, providing contextual insights, remediation guidance, and business impact assessments. This document describes the complete architecture, implementation plan, and testing strategy for the enrichment phase.

## Architecture

### Three-Phase Operation Model

```
┌─────────┐     ┌──────────┐     ┌────────┐
│  SCAN   │ --> │  ENRICH  │ --> │ REPORT │
└─────────┘     └──────────┘     └────────┘
     ↓               ↓                ↓
  findings      enrichments      final report
  (raw data)    (AI insights)    (combined)
```

### Command Structure

```bash
# Standard workflow
prismatic scan -c configs/client.yaml
prismatic enrich -s data/scans/2024-01-15-133214 --strategy smart-batch
prismatic report -s data/scans/2024-01-15-133214 -o reports/client-report.html

# Skip enrichment (cost-saving)
prismatic scan -c configs/client.yaml
prismatic report -s data/scans/2024-01-15-133214 --no-enrichment

# Re-enrich with different strategy
prismatic enrich -s data/scans/2024-01-15-133214 --strategy critical-only --force
```

## Data Storage Architecture

### Knowledge Base (Static/Cached)

```
data/
├── knowledge/
│   ├── index.json                          # Fast lookup index
│   ├── cves/
│   │   ├── 2023/
│   │   │   └── CVE-2023-1234.yaml        # CVE details
│   │   └── 2024/
│   │       └── CVE-2024-5678.yaml
│   ├── misconfigurations/
│   │   ├── aws/
│   │   │   ├── s3-public-access.yaml     # Common patterns
│   │   │   └── rds-no-encryption.yaml
│   │   └── kubernetes/
│   │       └── privileged-pods.yaml
│   └── patterns/
│       └── common-vulnerabilities.yaml    # Generic patterns
```

**Example CVE Entry:**
```yaml
# data/knowledge/cves/2023/CVE-2023-1234.yaml
id: CVE-2023-1234
created: 2024-01-10T10:00:00Z
updated: 2024-01-10T10:00:00Z
ttl: 90d
metadata:
  cvss_score: 8.5
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
  cwe: ["CWE-79", "CWE-116"]
  affected_products:
    - name: "Example Framework"
      versions: ["< 2.5.1", ">= 2.0.0"]
description: |
  Cross-site scripting vulnerability in Example Framework versions 2.0.0 to 2.5.0
  allows remote attackers to inject arbitrary web script.
technical_details: |
  The vulnerability exists in the template rendering engine where user input
  is not properly sanitized before being inserted into HTML templates.
generic_remediation:
  immediate: "Apply input validation and output encoding"
  short_term: "Update to version 2.5.1 or later"
  long_term: "Implement Content Security Policy (CSP)"
references:
  - "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"
  - "https://github.com/example/framework/security/advisories/GHSA-xxxx"
```

### Contextual Enrichments (Per-Scan)

```
data/
└── scans/
    └── 2024-01-15-133214/
        ├── metadata.json
        ├── findings.json
        ├── raw/
        └── enrichments/
            ├── metadata.json           # Enrichment run metadata
            ├── findings/               # Individual enrichments
            │   ├── abc123.json        # Per-finding enrichment
            │   └── def456.json
            └── summary.json           # Overall assessment
```

**Example Finding Enrichment:**
```json
{
  "finding_id": "abc123",
  "enriched_at": "2024-01-15T14:30:00Z",
  "llm_model": "claude-3-opus-20240229",
  "tokens_used": 1250,
  "context": {
    "service": "Payment API",
    "environment": "production",
    "data_classification": "PCI",
    "related_findings": ["def456", "ghi789"]
  },
  "analysis": {
    "business_impact": "Critical - Direct payment processing risk",
    "likelihood": "High - Public exploit available",
    "priority_score": 9.5,
    "contextual_notes": "This API processes 10K transactions/day"
  },
  "remediation": {
    "immediate_actions": [
      "Enable WAF rule 7000123",
      "Notify security team"
    ],
    "short_term": [
      "Schedule emergency patch for tonight",
      "Update to version 2.5.1"
    ],
    "long_term": [
      "Implement API versioning",
      "Add automated security testing"
    ],
    "estimated_effort": "4 hours",
    "dependencies": ["Maintenance window required"]
  }
}
```

## LLM Driver Architecture

### Interface Design

```go
// internal/enrichment/llm/driver.go
package llm

type Driver interface {
    // Enrich a batch of findings with context
    EnrichFindings(ctx context.Context, req EnrichmentRequest) (*EnrichmentResponse, error)
    
    // Get driver capabilities and limits
    GetCapabilities() Capabilities
    
    // Estimate token usage before making request
    EstimateTokens(req EnrichmentRequest) TokenEstimate
    
    // Health check
    Ping(ctx context.Context) error
}

type EnrichmentRequest struct {
    Findings      []FindingContext `json:"findings"`
    ScanContext   ScanContext      `json:"scan_context"`
    Strategy      string           `json:"strategy"`
    MaxTokens     int              `json:"max_tokens,omitempty"`
    Temperature   float32          `json:"temperature,omitempty"`
}

type FindingContext struct {
    Finding            models.Finding   `json:"finding"`
    KnowledgeBase      *KnowledgeEntry  `json:"knowledge_base,omitempty"`
    RelatedFindings    []string         `json:"related_findings,omitempty"`
    ResourceContext    interface{}      `json:"resource_context,omitempty"`
}

type Capabilities struct {
    MaxTokensPerRequest int      `json:"max_tokens_per_request"`
    SupportedStrategies []string `json:"supported_strategies"`
    CostPerToken        float64  `json:"cost_per_token"`
    RateLimits          RateLimits `json:"rate_limits"`
}
```

### Claude Code Driver Implementation

```go
// internal/enrichment/llm/claude_cli.go
package llm

import (
    "encoding/json"
    "os/exec"
    "fmt"
)

type ClaudeCLIDriver struct {
    modelName    string
    temperature  float32
    logger       logger.Logger
}

func NewClaudeCLIDriver(config ClaudeConfig) *ClaudeCLIDriver {
    return &ClaudeCLIDriver{
        modelName:   config.Model, // e.g., "opus", "sonnet"
        temperature: config.Temperature,
        logger:      config.Logger,
    }
}

func (d *ClaudeCLIDriver) EnrichFindings(ctx context.Context, req EnrichmentRequest) (*EnrichmentResponse, error) {
    // Build the prompt
    prompt := d.buildPrompt(req)
    
    // Execute claude CLI
    cmd := exec.CommandContext(ctx, "claude", 
        "-p", prompt,
        "--model", d.modelName,
        "--output-format", "json",
        "--max-turns", "1",
    )
    
    output, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("claude CLI error: %w", err)
    }
    
    // Parse response
    var response EnrichmentResponse
    if err := json.Unmarshal(output, &response); err != nil {
        return nil, fmt.Errorf("failed to parse claude response: %w", err)
    }
    
    return &response, nil
}

func (d *ClaudeCLIDriver) buildPrompt(req EnrichmentRequest) string {
    // Strategic prompt construction for optimal results
    template := `You are a security expert analyzing findings for a %s environment.

Context:
- Environment: %s
- Application: %s
- Data Types: %s

Analyze these security findings and provide enrichment in JSON format:

%s

For each finding provide:
1. business_impact: One sentence explaining the business risk
2. priority_score: 1-10 based on exploitability and impact
3. remediation: Specific steps (immediate/short_term/long_term)
4. estimated_effort: Time estimate for fix
5. contextual_notes: Any environment-specific considerations

Output pure JSON matching this structure:
{
  "findings": {
    "<finding_id>": {
      "business_impact": "string",
      "priority_score": number,
      "remediation": {
        "immediate": ["string"],
        "short_term": ["string"],
        "long_term": ["string"]
      },
      "estimated_effort": "string",
      "contextual_notes": "string"
    }
  },
  "overall_assessment": "string"
}`

    // Format with actual data
    return fmt.Sprintf(template,
        req.ScanContext.Environment,
        req.ScanContext.Environment,
        req.ScanContext.Application,
        req.ScanContext.DataTypes,
        d.formatFindings(req.Findings))
}
```

### Driver Registry

```go
// internal/enrichment/llm/registry.go
package llm

var drivers = map[string]DriverFactory{
    "claude-cli": NewClaudeCLIDriver,
    "openai-api": NewOpenAIDriver,     // Future
    "bedrock":    NewBedrockDriver,    // Future
    "ollama":     NewOllamaDriver,     // Future local option
}

func GetDriver(name string, config interface{}) (Driver, error) {
    factory, exists := drivers[name]
    if !exists {
        return nil, fmt.Errorf("unknown LLM driver: %s", name)
    }
    return factory(config), nil
}
```

## Token Optimization Strategies

### 1. Smart Batching

```go
// internal/enrichment/batch.go
type BatchStrategy interface {
    CreateBatches(findings []models.Finding) []FindingBatch
}

type SmartBatchStrategy struct {
    maxTokensPerBatch int
    tokenCounter      TokenCounter
}

func (s *SmartBatchStrategy) CreateBatches(findings []models.Finding) []FindingBatch {
    // Group by:
    // 1. Scanner type (all Trivy findings together)
    // 2. Resource type (all S3 findings together)  
    // 3. Severity (process critical first)
    // 4. Similarity (deduplicate similar issues)
    
    batches := []FindingBatch{}
    grouped := s.groupBySimilarity(findings)
    
    for _, group := range grouped {
        if len(group) > 10 {
            // Summarize large groups
            batch := FindingBatch{
                Type: "summary",
                Count: len(group),
                Sample: group[0],
                Pattern: s.extractPattern(group),
            }
            batches = append(batches, batch)
        } else {
            // Individual analysis for small groups
            batch := FindingBatch{
                Type: "detailed",
                Findings: group,
            }
            batches = append(batches, batch)
        }
    }
    
    return s.optimizeBatches(batches)
}
```

### 2. Caching Strategy

```go
// internal/enrichment/cache.go
type EnrichmentCache struct {
    knowledgeBase *KnowledgeBase
    contextCache  map[string]*EnrichmentResult // LRU cache
    ttl           time.Duration
}

func (c *EnrichmentCache) GetOrEnrich(finding models.Finding, enricher Enricher) (*EnrichmentResult, error) {
    // Check knowledge base first (permanent cache)
    if kb := c.knowledgeBase.Lookup(finding); kb != nil {
        if !kb.IsExpired() {
            return kb.ToEnrichment(), nil
        }
    }
    
    // Check context cache (temporary)
    cacheKey := finding.GenerateStableID()
    if cached, exists := c.contextCache[cacheKey]; exists {
        if time.Since(cached.Timestamp) < c.ttl {
            return cached, nil
        }
    }
    
    // Enrich and cache
    result, err := enricher.Enrich(finding)
    if err != nil {
        return nil, err
    }
    
    c.contextCache[cacheKey] = result
    return result, nil
}
```

### 3. Progressive Enhancement

```go
// internal/enrichment/progressive.go
type ProgressiveEnricher struct {
    strategies []EnrichmentStrategy
}

var defaultStrategies = []EnrichmentStrategy{
    {Name: "critical-only", Filter: func(f Finding) bool { return f.Severity >= CRITICAL }},
    {Name: "high-impact", Filter: func(f Finding) bool { return f.InProduction() }},
    {Name: "compliance", Filter: func(f Finding) bool { return f.HasComplianceTag() }},
    {Name: "all", Filter: func(f Finding) bool { return true }},
}
```

## Testing Strategy

### 1. Unit Tests

```go
// internal/enrichment/enricher_test.go
func TestSmartBatching(t *testing.T) {
    findings := []models.Finding{
        // 50 similar S3 bucket findings
        generateS3Findings(50),
        // 10 different CVEs
        generateCVEFindings(10),
    }
    
    strategy := &SmartBatchStrategy{maxTokensPerBatch: 4000}
    batches := strategy.CreateBatches(findings)
    
    // Should create 2 batches: 1 summary for S3, 1 detailed for CVEs
    assert.Equal(t, 2, len(batches))
    assert.Equal(t, "summary", batches[0].Type)
    assert.Equal(t, 50, batches[0].Count)
}

func TestCachingBehavior(t *testing.T) {
    cache := NewEnrichmentCache(time.Hour)
    enricher := &MockEnricher{
        CallCount: 0,
        Response: &EnrichmentResult{...},
    }
    
    finding := models.Finding{ID: "test-123"}
    
    // First call should hit enricher
    result1, _ := cache.GetOrEnrich(finding, enricher)
    assert.Equal(t, 1, enricher.CallCount)
    
    // Second call should hit cache
    result2, _ := cache.GetOrEnrich(finding, enricher)
    assert.Equal(t, 1, enricher.CallCount) // No additional calls
    assert.Equal(t, result1, result2)
}
```

### 2. Integration Tests

```go
// internal/enrichment/llm/claude_cli_test.go
func TestClaudeCLIIntegration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping Claude CLI integration test")
    }
    
    // Check if claude CLI is available
    if _, err := exec.LookPath("claude"); err != nil {
        t.Skip("claude CLI not found")
    }
    
    driver := NewClaudeCLIDriver(ClaudeConfig{
        Model: "claude-3-haiku-20240307", // Use cheaper model for tests
    })
    
    req := EnrichmentRequest{
        Findings: []FindingContext{{
            Finding: models.Finding{
                ID:       "test-001",
                Scanner:  "trivy",
                Severity: "HIGH",
                Title:    "Outdated OpenSSL version",
            },
        }},
        ScanContext: ScanContext{
            Environment: "test",
            Application: "test-app",
        },
    }
    
    resp, err := driver.EnrichFindings(context.Background(), req)
    assert.NoError(t, err)
    assert.NotNil(t, resp)
    assert.Contains(t, resp.Findings, "test-001")
}
```

### 3. Mock LLM Driver for Testing

```go
// internal/enrichment/llm/mock_driver.go
type MockLLMDriver struct {
    responses map[string]EnrichmentResponse
    calls     []EnrichmentRequest
    mu        sync.Mutex
}

func (m *MockLLMDriver) EnrichFindings(ctx context.Context, req EnrichmentRequest) (*EnrichmentResponse, error) {
    m.mu.Lock()
    m.calls = append(m.calls, req)
    m.mu.Unlock()
    
    // Return canned responses based on finding patterns
    if strings.Contains(req.Findings[0].Finding.Title, "CVE") {
        return &m.responses["cve-response"], nil
    }
    
    return &m.responses["default"], nil
}

// Use in tests
func TestEnrichmentOrchestrator(t *testing.T) {
    mock := &MockLLMDriver{
        responses: map[string]EnrichmentResponse{
            "default": {
                Findings: map[string]FindingEnrichment{
                    "test-001": {
                        BusinessImpact: "Test impact",
                        PriorityScore:  7,
                    },
                },
            },
        },
    }
    
    orchestrator := NewOrchestrator(mock)
    // Test orchestration logic without real LLM calls
}
```

### 4. Cost Control Testing

```go
// internal/enrichment/cost_test.go
func TestTokenBudgetEnforcement(t *testing.T) {
    enricher := NewEnricher(EnricherConfig{
        MaxTokensPerRun: 10000,
        TokenCounter:    &MockTokenCounter{},
    })
    
    // Generate findings that would exceed budget
    findings := generateManyFindings(1000)
    
    result, err := enricher.EnrichAll(findings)
    assert.NoError(t, err)
    assert.LessOrEqual(t, result.TotalTokensUsed, 10000)
    assert.Less(t, len(result.EnrichedFindings), 1000) // Some skipped
}
```

## Configuration

### Client Configuration

```yaml
# configs/client.yaml
enrichment:
  enabled: true
  driver: "claude-cli"
  driver_config:
    model: "claude-3-opus-20240229"
    temperature: 0.3
  strategy: "smart-batch"
  token_budget: 50000
  cache_ttl: "720h"  # 30 days
  
  # Selective enrichment
  include:
    severities: ["CRITICAL", "HIGH"]
    scanners: ["trivy", "checkov", "prowler"]
    environments: ["production", "staging"]
  
  exclude:
    patterns:
      - "test-*"
      - "*-dev"
    finding_ids:
      - "known-false-positive-123"
```

### Command Configuration

```go
// cmd/enrich/enrich.go
type EnrichConfig struct {
    ScanPath     string
    Strategy     string
    Force        bool
    DryRun       bool
    TokenBudget  int
    Driver       string
    DriverConfig map[string]interface{}
}

var enrichCmd = &cobra.Command{
    Use:   "enrich",
    Short: "Enrich scan findings with AI analysis",
    RunE: func(cmd *cobra.Command, args []string) error {
        config := &EnrichConfig{
            ScanPath:    cmd.Flag("scan").Value.String(),
            Strategy:    cmd.Flag("strategy").Value.String(),
            Force:       cmd.Flag("force").Value.String() == "true",
            DryRun:      cmd.Flag("dry-run").Value.String() == "true",
            TokenBudget: cmd.Flag("token-budget").Value.String(),
        }
        
        if config.DryRun {
            // Show what would be enriched without spending tokens
            return showEnrichmentPlan(config)
        }
        
        return runEnrichment(config)
    },
}
```

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1)
- [ ] Create enrichment package structure
- [ ] Implement knowledge base storage
- [ ] Build LLM driver interface
- [ ] Create Claude CLI driver
- [ ] Add basic unit tests

### Phase 2: Smart Batching (Week 2)
- [ ] Implement finding grouping algorithms
- [ ] Create token counting utilities
- [ ] Build batch optimization logic
- [ ] Add caching layer
- [ ] Integration tests with mock driver

### Phase 3: CLI Integration (Week 3)
- [ ] Create `prismatic enrich` command
- [ ] Add progress UI for long-running enrichment
- [ ] Implement dry-run mode
- [ ] Connect to report generation
- [ ] End-to-end testing

### Phase 4: Optimization (Week 4)
- [ ] Performance profiling
- [ ] Token usage analytics
- [ ] Knowledge base seeding
- [ ] Documentation and examples
- [ ] Production hardening

## Future Enhancements

### 1. Additional LLM Drivers
```go
// OpenAI API driver for GPT-4
type OpenAIDriver struct {
    apiKey string
    model  string
}

// AWS Bedrock for Claude via API
type BedrockDriver struct {
    region string
    model  string
}

// Local Ollama for cost-free enrichment
type OllamaDriver struct {
    endpoint string
    model    string
}
```

### 2. Streaming Enrichment
```go
// For real-time enrichment during scanning
type StreamingEnricher interface {
    EnrichStream(findings <-chan Finding) <-chan EnrichedFinding
}
```

### 3. Historical Trending
```go
// Track how findings evolve over time
type TrendAnalyzer interface {
    AnalyzeTrends(client string, timeRange TimeRange) TrendReport
}
```

### 4. Collaborative Knowledge Base
- Shared CVE enrichments across Prismatic instances
- Community-contributed remediation patterns
- Automated knowledge base updates from security feeds

## Success Metrics

1. **Token Efficiency**: < 100 tokens per finding on average
2. **Cache Hit Rate**: > 60% for common vulnerabilities
3. **Enrichment Quality**: Actionable remediation in > 90% of findings
4. **Performance**: < 5 minutes for 1000 findings
5. **Cost Control**: Stay within configured token budgets

## Security Considerations

1. **No Sensitive Data to LLMs**: Strip PII/credentials before enrichment
2. **Audit Trail**: Log all LLM interactions
3. **Rate Limiting**: Prevent runaway token usage
4. **Output Validation**: Verify LLM responses are well-formed
5. **Fallback Strategy**: Graceful degradation if LLM unavailable

---

This design provides a complete blueprint for implementing the enrichment feature with testability, extensibility, and cost-efficiency at its core.