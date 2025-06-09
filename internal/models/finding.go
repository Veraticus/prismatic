// Package models contains data structures for Prismatic security findings.
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Finding represents a normalized security finding from any scanner.
type Finding struct {
	PublishedDate      time.Time           `json:"published_date,omitempty"`
	DiscoveredDate     time.Time           `json:"discovered_date"`
	Metadata           map[string]string   `json:"metadata,omitempty"`
	RemediationDetails *RemediationDetails `json:"remediation_details,omitempty"`
	BusinessContext    *BusinessContext    `json:"business_context,omitempty"`
	Remediation        string              `json:"remediation"`
	SuppressionReason  string              `json:"suppression_reason,omitempty"`
	Type               string              `json:"type"`
	Framework          string              `json:"framework,omitempty"`
	Resource           string              `json:"resource"`
	Title              string              `json:"title"`
	ID                 string              `json:"id"`
	Description        string              `json:"description"`
	Scanner            string              `json:"scanner"`
	Location           string              `json:"location,omitempty"`
	Impact             string              `json:"impact"`
	Comment            string              `json:"comment,omitempty"`
	Severity           string              `json:"severity"`
	OriginalSeverity   string              `json:"original_severity,omitempty"`
	References         []string            `json:"references"`
	Suppressed         bool                `json:"suppressed"`
}

// ScanResult represents the output from a single scanner.
type ScanResult struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Scanner   string    `json:"scanner"`
	Version   string    `json:"version"`
	Error     string    `json:"error,omitempty"`
	RawOutput []byte    `json:"-"`
	Findings  []Finding `json:"findings"`
}

// ScanMetadata represents overall scan information.
type ScanMetadata struct {
	StartTime   time.Time              `json:"start_time"`
	EndTime     time.Time              `json:"end_time"`
	Results     map[string]*ScanResult `json:"results"`
	ID          string                 `json:"id"`
	ClientName  string                 `json:"client_name"`
	Environment string                 `json:"environment"`
	ConfigFile  string                 `json:"config_file"`
	Scanners    []string               `json:"scanners"`
	Summary     ScanSummary            `json:"summary"`
}

// ScanSummary provides high-level statistics.
type ScanSummary struct {
	BySeverity      map[string]int `json:"by_severity"`
	ByScanner       map[string]int `json:"by_scanner"`
	FailedScanners  []string       `json:"failed_scanners"`
	TotalFindings   int            `json:"total_findings"`
	SuppressedCount int            `json:"suppressed_count"`
}

// GenerateFindingID creates a stable, deterministic ID for a finding
// This allows consistent suppression and tracking across scans.
func GenerateFindingID(scanner, findingType, resource, location string) string {
	core := fmt.Sprintf("%s:%s:%s:%s", scanner, findingType, resource, location)
	hash := sha256.Sum256([]byte(core))
	return hex.EncodeToString(hash[:8]) // First 8 bytes for readability
}

// NewFinding creates a new finding with a generated ID.
func NewFinding(scanner, findingType, resource, location string) *Finding {
	return &Finding{
		ID:             GenerateFindingID(scanner, findingType, resource, location),
		Scanner:        scanner,
		Type:           findingType,
		Resource:       resource,
		Location:       location,
		Metadata:       make(map[string]string),
		DiscoveredDate: time.Now(),      // Default to current time, scanners can override
		Severity:       SeverityUnknown, // Set a default that will be overridden
	}
}

// WithSeverity sets the severity with automatic normalization.
func (f *Finding) WithSeverity(severity string) *Finding {
	f.Severity = NormalizeSeverity(severity)
	return f
}

// WithTitle sets the title.
func (f *Finding) WithTitle(title string) *Finding {
	f.Title = title
	return f
}

// WithDescription sets the description.
func (f *Finding) WithDescription(description string) *Finding {
	f.Description = description
	return f
}

// IsValid checks if a finding has all required fields.
func (f *Finding) IsValid() error {
	if f.Scanner == "" {
		return fmt.Errorf("finding missing required field: scanner")
	}
	if f.Type == "" {
		return fmt.Errorf("finding missing required field: type")
	}
	if f.Severity == "" {
		return fmt.Errorf("finding missing required field: severity")
	}
	if f.Title == "" {
		return fmt.Errorf("finding missing required field: title")
	}
	if f.Resource == "" {
		return fmt.Errorf("finding missing required field: resource")
	}
	return nil
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

// NormalizeSeverity ensures severity values are consistent.
func NormalizeSeverity(severity string) string {
	// Convert to lowercase for case-insensitive comparison
	lower := strings.ToLower(severity)

	switch lower {
	case "critical", "very-high", "very high", "veryhigh":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info", "informational", "negligible":
		return SeverityInfo
	case "unknown":
		return SeverityUnknown
	default:
		return SeverityUnknown
	}
}
