package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
)

// ClaudeCLIDriver implements the Driver interface using the Claude CLI.
type ClaudeCLIDriver struct {
	model       string
	temperature float64
	maxTokens   int
}

// NewClaudeCLIDriver creates a new Claude CLI driver.
func NewClaudeCLIDriver() *ClaudeCLIDriver {
	return &ClaudeCLIDriver{
		model:       "sonnet", // Default to Sonnet for cost efficiency
		temperature: 0.3,      // Lower temperature for more consistent output
		maxTokens:   4000,     // Default max tokens
	}
}

// Configure implements Driver interface.
func (d *ClaudeCLIDriver) Configure(config map[string]interface{}) error {
	if model, ok := config["model"].(string); ok {
		d.model = model
	}

	if temp, ok := config["temperature"].(float64); ok {
		d.temperature = temp
	}

	if maxTokens, ok := config["max_tokens"].(float64); ok {
		d.maxTokens = int(maxTokens)
	} else if maxTokens, ok := config["max_tokens"].(int); ok {
		d.maxTokens = maxTokens
	}

	return nil
}

// Enrich implements Driver interface.
func (d *ClaudeCLIDriver) Enrich(ctx context.Context, findings []models.Finding, prompt string) ([]enrichment.FindingEnrichment, error) {
	// Check if claude CLI is available
	if err := d.HealthCheck(ctx); err != nil {
		return nil, fmt.Errorf("claude CLI not available: %w", err)
	}

	// Build the command
	args := []string{
		"--model", d.getModelFlag(),
		"--output-format", "json",
		"--max-turns", "1",
		"--temperature", fmt.Sprintf("%.2f", d.temperature),
	}

	if d.maxTokens > 0 {
		args = append(args, "--max-tokens", fmt.Sprintf("%d", d.maxTokens))
	}

	// Create command with context
	cmd := exec.CommandContext(ctx, "claude", args...)

	// Set up stdin with the prompt
	cmd.Stdin = strings.NewReader(prompt)

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run the command
	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	if err != nil {
		return nil, fmt.Errorf("claude CLI failed: %w (stderr: %s)", err, stderr.String())
	}

	// Parse the JSON response
	var response claudeResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return nil, fmt.Errorf("failed to parse claude response: %w (output: %s)", err, stdout.String())
	}

	// Extract enrichments from the response
	enrichments, err := d.parseEnrichments(response, findings)
	if err != nil {
		return nil, fmt.Errorf("failed to parse enrichments: %w", err)
	}

	// Update metadata
	for i := range enrichments {
		enrichments[i].EnrichedAt = time.Now()
		enrichments[i].LLMModel = d.getModelName()
		enrichments[i].TokensUsed = response.Usage.OutputTokens + response.Usage.InputTokens

		// Add timing context
		if enrichments[i].Context == nil {
			enrichments[i].Context = make(map[string]interface{})
		}
		enrichments[i].Context["processing_time_ms"] = duration.Milliseconds()
	}

	return enrichments, nil
}

// GetCapabilities implements Driver interface.
func (d *ClaudeCLIDriver) GetCapabilities() Capabilities {
	// Model-specific capabilities
	capabilities := map[string]Capabilities{
		"opus": {
			MaxTokensPerRequest:     200000,
			MaxTokensPerResponse:    4096,
			SupportsJSONMode:        true,
			SupportsFunctionCalling: false,
			ModelName:               "claude-3-opus-20240229",
			CostPer1KTokens:         0.015, // $15 per 1M input tokens
		},
		"sonnet": {
			MaxTokensPerRequest:     200000,
			MaxTokensPerResponse:    4096,
			SupportsJSONMode:        true,
			SupportsFunctionCalling: false,
			ModelName:               "claude-3-5-sonnet-20241022",
			CostPer1KTokens:         0.003, // $3 per 1M input tokens
		},
		"haiku": {
			MaxTokensPerRequest:     200000,
			MaxTokensPerResponse:    4096,
			SupportsJSONMode:        true,
			SupportsFunctionCalling: false,
			ModelName:               "claude-3-haiku-20240307",
			CostPer1KTokens:         0.00025, // $0.25 per 1M input tokens
		},
	}

	if cap, ok := capabilities[d.model]; ok {
		return cap
	}

	// Default to Sonnet capabilities
	return capabilities["sonnet"]
}

// EstimateTokens implements Driver interface.
func (d *ClaudeCLIDriver) EstimateTokens(prompt string) (int, error) {
	// Simple estimation: ~4 characters per token
	// This is a rough estimate; actual tokenization varies
	tokens := len(prompt) / 4

	// Add some buffer for response tokens
	responseBuffer := 1000

	return tokens + responseBuffer, nil
}

// HealthCheck implements Driver interface.
func (d *ClaudeCLIDriver) HealthCheck(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "claude", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("claude CLI not found or not working: %w (output: %s)", err, output)
	}
	return nil
}

// getModelFlag converts the model name to the CLI flag format.
func (d *ClaudeCLIDriver) getModelFlag() string {
	// The claude CLI uses simple model names
	return d.model
}

// getModelName returns the full model name.
func (d *ClaudeCLIDriver) getModelName() string {
	return d.GetCapabilities().ModelName
}

// claudeResponse represents the JSON response from Claude CLI.
type claudeResponse struct {
	Content string `json:"content"`
	Model   string `json:"model"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// parseEnrichments extracts enrichments from Claude's response.
func (d *ClaudeCLIDriver) parseEnrichments(response claudeResponse, findings []models.Finding) ([]enrichment.FindingEnrichment, error) {
	// Extract JSON from the content
	content := response.Content

	// Find JSON block in the response
	startIdx := strings.Index(content, "[")
	endIdx := strings.LastIndex(content, "]")

	if startIdx == -1 || endIdx == -1 || startIdx >= endIdx {
		return nil, fmt.Errorf("no valid JSON array found in response")
	}

	jsonContent := content[startIdx : endIdx+1]

	// Parse the enrichment JSON
	var rawEnrichments []struct {
		FindingID string `json:"finding_id"`
		Analysis  struct {
			BusinessImpact    string   `json:"business_impact"`
			PriorityReasoning string   `json:"priority_reasoning"`
			TechnicalDetails  string   `json:"technical_details"`
			ContextualNotes   string   `json:"contextual_notes"`
			RelatedFindings   []string `json:"related_findings"`
			Dependencies      []string `json:"dependencies"`
			PriorityScore     float64  `json:"priority_score"`
		} `json:"analysis"`
		Remediation struct {
			EstimatedEffort    string   `json:"estimated_effort"`
			Immediate          []string `json:"immediate"`
			ShortTerm          []string `json:"short_term"`
			LongTerm           []string `json:"long_term"`
			ValidationSteps    []string `json:"validation_steps"`
			AutomationPossible bool     `json:"automation_possible"`
		} `json:"remediation"`
	}

	if err := json.Unmarshal([]byte(jsonContent), &rawEnrichments); err != nil {
		return nil, fmt.Errorf("failed to parse enrichment JSON: %w", err)
	}

	// Convert to FindingEnrichment
	enrichments := make([]enrichment.FindingEnrichment, 0, len(rawEnrichments))

	// Create a map of finding IDs for validation
	findingMap := make(map[string]bool)
	for _, f := range findings {
		findingMap[f.ID] = true
	}

	for _, raw := range rawEnrichments {
		// Skip if finding ID doesn't match (unless it's a group summary)
		if raw.FindingID != "group_summary" && !findingMap[raw.FindingID] {
			continue
		}

		e := enrichment.FindingEnrichment{
			FindingID: raw.FindingID,
			Analysis: enrichment.Analysis{
				BusinessImpact:    raw.Analysis.BusinessImpact,
				PriorityScore:     raw.Analysis.PriorityScore,
				PriorityReasoning: raw.Analysis.PriorityReasoning,
				TechnicalDetails:  raw.Analysis.TechnicalDetails,
				RelatedFindings:   raw.Analysis.RelatedFindings,
				Dependencies:      raw.Analysis.Dependencies,
				ContextualNotes:   raw.Analysis.ContextualNotes,
			},
			Remediation: enrichment.Remediation{
				Immediate:          raw.Remediation.Immediate,
				ShortTerm:          raw.Remediation.ShortTerm,
				LongTerm:           raw.Remediation.LongTerm,
				EstimatedEffort:    raw.Remediation.EstimatedEffort,
				AutomationPossible: raw.Remediation.AutomationPossible,
				ValidationSteps:    raw.Remediation.ValidationSteps,
			},
		}

		enrichments = append(enrichments, e)
	}

	return enrichments, nil
}

// init registers the driver.
func init() {
	DefaultRegistry.Register("claude-cli", func() Driver {
		return NewClaudeCLIDriver()
	})
}
