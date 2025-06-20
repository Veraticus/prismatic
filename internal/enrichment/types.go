package enrichment

import (
	"time"
)

// FindingEnrichment contains the enriched information for a finding.
type FindingEnrichment struct {
	EnrichedAt  time.Time      `json:"enriched_at"`
	Context     map[string]any `json:"context"`
	Analysis    Analysis       `json:"analysis"`
	FindingID   string         `json:"finding_id"`
	LLMModel    string         `json:"llm_model"`
	Remediation Remediation    `json:"remediation"`
	TokensUsed  int            `json:"tokens_used"`
}

// Analysis contains AI-generated analysis of a finding.
type Analysis struct {
	BusinessImpact    string   `json:"business_impact"`
	PriorityReasoning string   `json:"priority_reasoning"`
	TechnicalDetails  string   `json:"technical_details"`
	ContextualNotes   string   `json:"contextual_notes,omitempty"`
	RelatedFindings   []string `json:"related_findings,omitempty"`
	Dependencies      []string `json:"dependencies,omitempty"`
	PriorityScore     float64  `json:"priority_score"`
}

// Remediation contains remediation guidance.
type Remediation struct {
	EstimatedEffort    string   `json:"estimated_effort"`
	Immediate          []string `json:"immediate"`
	ShortTerm          []string `json:"short_term"`
	LongTerm           []string `json:"long_term"`
	ValidationSteps    []string `json:"validation_steps,omitempty"`
	AutomationPossible bool     `json:"automation_possible"`
}

// Metadata contains metadata about an enrichment run.
type Metadata struct {
	StartedAt        time.Time `json:"started_at"`
	CompletedAt      time.Time `json:"completed_at"`
	RunID            string    `json:"run_id"`
	Strategy         string    `json:"strategy"`
	Driver           string    `json:"driver"`
	LLMModel         string    `json:"llm_model"`
	Errors           []string  `json:"errors,omitempty"`
	TotalFindings    int       `json:"total_findings"`
	EnrichedFindings int       `json:"enriched_findings"`
	TotalTokensUsed  int       `json:"total_tokens_used"`
}
