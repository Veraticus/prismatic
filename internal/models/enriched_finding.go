package models

// EnrichedFinding extends Finding with business context.
type EnrichedFinding struct {
	BusinessContext    BusinessContext    `json:"business_context,omitempty"`
	RemediationDetails RemediationDetails `json:"remediation_details,omitempty"`
	Finding
}

// BusinessContext contains business-relevant information about a finding.
type BusinessContext struct {
	Owner              string   `json:"owner,omitempty"`
	DataClassification string   `json:"data_classification,omitempty"`
	BusinessImpact     string   `json:"business_impact,omitempty"`
	ComplianceImpact   []string `json:"compliance_impact,omitempty"`
}

// RemediationDetails provides additional remediation information.
type RemediationDetails struct {
	Effort      string `json:"effort,omitempty"`
	TicketURL   string `json:"ticket_url,omitempty"`
	AutoFixable bool   `json:"auto_fixable"`
}

// EnrichFinding creates an enriched finding from a base finding.
func EnrichFinding(f Finding) *EnrichedFinding {
	return &EnrichedFinding{
		Finding: f,
	}
}

// SetBusinessContext adds business context to the finding.
func (ef *EnrichedFinding) SetBusinessContext(ctx BusinessContext) {
	ef.BusinessContext = ctx
}

// SetRemediationDetails adds remediation details to the finding.
func (ef *EnrichedFinding) SetRemediationDetails(details RemediationDetails) {
	ef.RemediationDetails = details
}
