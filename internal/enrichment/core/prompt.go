package core

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/joshsymonds/prismatic/internal/enrichment/batch"
	"github.com/joshsymonds/prismatic/internal/enrichment/knowledge"
	"github.com/joshsymonds/prismatic/internal/models"
)

// buildEnrichmentPrompt creates the prompt for enriching findings.
func buildEnrichmentPrompt(findings []models.Finding, batch *batch.Batch, knowledgeEntries []*knowledge.Entry, clientContext map[string]any) string {
	var sb strings.Builder

	// System prompt
	sb.WriteString("You are a security expert analyzing findings from security scans. ")
	sb.WriteString("Your task is to provide contextual enrichment for each finding, including business impact, ")
	sb.WriteString("priority scoring, and actionable remediation guidance.\n\n")

	// Client context
	if len(clientContext) > 0 {
		sb.WriteString("## Client Context\n")
		contextJSON, _ := json.MarshalIndent(clientContext, "", "  ")
		sb.Write(contextJSON)
		sb.WriteString("\n\n")
	}

	// Knowledge base entries
	if len(knowledgeEntries) > 0 {
		sb.WriteString("## Relevant Knowledge Base Entries\n")
		for _, entry := range knowledgeEntries {
			sb.WriteString(fmt.Sprintf("### %s\n", entry.ID))
			sb.WriteString(fmt.Sprintf("Type: %s\n", entry.Type))
			sb.WriteString(fmt.Sprintf("Description: %s\n", entry.Description))
			if entry.GenericRemediation != nil {
				sb.WriteString("Generic Remediation:\n")
				sb.WriteString(fmt.Sprintf("- Immediate: %s\n", entry.GenericRemediation.Immediate))
				sb.WriteString(fmt.Sprintf("- Short Term: %s\n", entry.GenericRemediation.ShortTerm))
				sb.WriteString(fmt.Sprintf("- Long Term: %s\n", entry.GenericRemediation.LongTerm))
			}
			sb.WriteString("\n")
		}
	}

	// Findings
	if batch.ShouldSummarize {
		sb.WriteString(fmt.Sprintf("## Finding Summary (Group: %s)\n", batch.GroupKey))
		sb.WriteString(fmt.Sprintf("Reason for summarization: %s\n", batch.SummaryReason))
		sb.WriteString(fmt.Sprintf("Total findings in group: %d\n\n", len(findings)))

		// Show first few findings as examples
		exampleCount := 3
		if len(findings) < exampleCount {
			exampleCount = len(findings)
		}

		sb.WriteString("Example findings:\n")
		for i := 0; i < exampleCount; i++ {
			f := findings[i]
			sb.WriteString(fmt.Sprintf("- %s: %s (Severity: %s)\n", f.ID, f.Title, f.Severity))
		}
	} else {
		sb.WriteString("## Findings to Analyze\n")
		for i, f := range findings {
			sb.WriteString(fmt.Sprintf("### Finding %d (ID: %s)\n", i+1, f.ID))
			sb.WriteString(fmt.Sprintf("Title: %s\n", f.Title))
			sb.WriteString(fmt.Sprintf("Description: %s\n", f.Description))
			sb.WriteString(fmt.Sprintf("Severity: %s\n", f.Severity))
			sb.WriteString(fmt.Sprintf("Scanner: %s\n", f.Scanner))
			sb.WriteString(fmt.Sprintf("Type: %s\n", f.Type))
			sb.WriteString(fmt.Sprintf("Resource: %s\n", f.Resource))

			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf("Scanner Remediation: %s\n", f.Remediation))
			}

			sb.WriteString("\n")
		}
	}

	// Instructions for output format
	sb.WriteString("\n## Instructions\n")
	sb.WriteString("For each finding (or for the group if summarizing), provide enrichment in the following JSON format:\n\n")

	sb.WriteString("```json\n")
	sb.WriteString("[\n")
	sb.WriteString("  {\n")
	sb.WriteString("    \"finding_id\": \"<finding_id or 'group_summary'>\",\n")
	sb.WriteString("    \"analysis\": {\n")
	sb.WriteString("      \"business_impact\": \"<one sentence explaining business risk>\",\n")
	sb.WriteString("      \"priority_score\": <1-10 based on exploitability and impact>,\n")
	sb.WriteString("      \"priority_reasoning\": \"<brief explanation of the priority score>\",\n")
	sb.WriteString("      \"technical_details\": \"<additional technical context if relevant>\",\n")
	sb.WriteString("      \"related_findings\": [\"<other finding IDs if related>\"],\n")
	sb.WriteString("      \"dependencies\": [\"<prerequisite fixes if any>\"],\n")
	sb.WriteString("      \"contextual_notes\": \"<environment-specific considerations>\"\n")
	sb.WriteString("    },\n")
	sb.WriteString("    \"remediation\": {\n")
	sb.WriteString("      \"immediate\": [\"<steps to take immediately>\"],\n")
	sb.WriteString("      \"short_term\": [\"<steps for next sprint/release>\"],\n")
	sb.WriteString("      \"long_term\": [\"<architectural improvements>\"],\n")
	sb.WriteString("      \"estimated_effort\": \"<time estimate e.g. '2 hours', '1 day', '1 week'>\",\n")
	sb.WriteString("      \"automation_possible\": <true/false>,\n")
	sb.WriteString("      \"validation_steps\": [\"<steps to verify the fix>\"]\n")
	sb.WriteString("    }\n")
	sb.WriteString("  }\n")
	sb.WriteString("]\n")
	sb.WriteString("```\n\n")

	sb.WriteString("Guidelines:\n")
	sb.WriteString("- Focus on practical, actionable guidance\n")
	sb.WriteString("- Consider the client context when assessing business impact\n")
	sb.WriteString("- Prioritize based on real-world exploitability and impact\n")
	sb.WriteString("- Provide specific remediation steps, not generic advice\n")
	sb.WriteString("- For summaries, provide aggregate analysis and common remediation patterns\n")
	sb.WriteString("- Ensure all JSON is valid and properly formatted\n")

	return sb.String()
}
