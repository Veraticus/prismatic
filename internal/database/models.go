package database

import (
	"database/sql"
	"encoding/json"
	"time"
)

// ScannerFlag represents a bitmask for enabled scanners.
type ScannerFlag int

// Scanner flags for enabled scanners.
const (
	ScannerProwler ScannerFlag = 1 << iota
	ScannerTrivy
	ScannerKubescape
	ScannerNuclei
	ScannerGitleaks
	ScannerCheckov
)

// Scanner names for database storage.
const (
	ScannerNameProwler   = "prowler"
	ScannerNameTrivy     = "trivy"
	ScannerNameKubescape = "kubescape"
	ScannerNameNuclei    = "nuclei"
	ScannerNameGitleaks  = "gitleaks"
	ScannerNameCheckov   = "checkov"
)

// ScanStatus represents the status of a scan.
type ScanStatus string

// Scan status values.
const (
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
)

// Severity represents finding severity levels.
type Severity string

// Finding severity levels.
const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Scan represents a security scan in the database.
type Scan struct {
	StartedAt    time.Time
	CompletedAt  sql.NullTime
	Status       ScanStatus
	AWSProfile   sql.NullString
	AWSRegions   []string
	KubeContext  sql.NullString
	ErrorDetails sql.NullString
	ID           int64
	Scanners     ScannerFlag
}

// Finding represents a security finding in the database.
type Finding struct {
	CreatedAt        time.Time
	Scanner          string
	Severity         Severity
	Title            string
	Description      string
	Resource         string
	TechnicalDetails json.RawMessage
	ID               int64
	ScanID           int64
}

// Suppression represents a finding suppression.
type Suppression struct {
	SuppressedAt time.Time
	Reason       string
	SuppressedBy string
	ID           int64
	FindingID    int64
}

// ScanFilter provides filtering options for listing scans.
type ScanFilter struct {
	Status     *ScanStatus
	AWSProfile *string
	Limit      int
	Offset     int
}

// FindingFilter provides filtering options for querying findings.
type FindingFilter struct {
	Scanner  *string
	Severity *Severity
	Resource *string
	Limit    int
	Offset   int
}

// FindingCounts represents counts of findings by severity.
type FindingCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
}

// HasScanner checks if a specific scanner is enabled.
func (s ScannerFlag) HasScanner(scanner ScannerFlag) bool {
	return s&scanner != 0
}

// AddScanner adds a scanner to the flags.
func (s *ScannerFlag) AddScanner(scanner ScannerFlag) {
	*s |= scanner
}

// RemoveScanner removes a scanner from the flags.
func (s *ScannerFlag) RemoveScanner(scanner ScannerFlag) {
	*s &^= scanner
}

// GetEnabledScanners returns a list of enabled scanner names.
func (s ScannerFlag) GetEnabledScanners() []string {
	var scanners []string

	if s.HasScanner(ScannerProwler) {
		scanners = append(scanners, ScannerNameProwler)
	}
	if s.HasScanner(ScannerTrivy) {
		scanners = append(scanners, ScannerNameTrivy)
	}
	if s.HasScanner(ScannerKubescape) {
		scanners = append(scanners, ScannerNameKubescape)
	}
	if s.HasScanner(ScannerNuclei) {
		scanners = append(scanners, ScannerNameNuclei)
	}
	if s.HasScanner(ScannerGitleaks) {
		scanners = append(scanners, ScannerNameGitleaks)
	}
	if s.HasScanner(ScannerCheckov) {
		scanners = append(scanners, ScannerNameCheckov)
	}

	return scanners
}

// ScannerFlagFromNames creates a ScannerFlag from scanner names.
func ScannerFlagFromNames(names []string) ScannerFlag {
	var flags ScannerFlag

	for _, name := range names {
		switch name {
		case ScannerNameProwler:
			flags.AddScanner(ScannerProwler)
		case ScannerNameTrivy:
			flags.AddScanner(ScannerTrivy)
		case ScannerNameKubescape:
			flags.AddScanner(ScannerKubescape)
		case ScannerNameNuclei:
			flags.AddScanner(ScannerNuclei)
		case ScannerNameGitleaks:
			flags.AddScanner(ScannerGitleaks)
		case ScannerNameCheckov:
			flags.AddScanner(ScannerCheckov)
		}
	}

	return flags
}

// ScannerOutput represents raw scanner output in the database.
type ScannerOutput struct {
	CreatedAt time.Time
	Scanner   string
	RawOutput string
	ID        int64
	ScanID    int64
}

// FindingEnrichment represents AI enrichment for a finding.
type FindingEnrichment struct {
	CreatedAt        time.Time
	FindingID        string
	BusinessImpact   sql.NullString
	RemediationSteps sql.NullString
	EstimatedEffort  sql.NullString
	AIAnalysis       json.RawMessage
	RiskScore        sql.NullInt64
	ID               int64
	ScanID           int64
}

// ScanMetadata represents additional scan metadata.
type ScanMetadata struct {
	CreatedAt       time.Time
	ClientName      sql.NullString
	Environment     sql.NullString
	Configuration   json.RawMessage
	Summary         json.RawMessage
	ScannerVersions json.RawMessage
	ID              int64
	ScanID          int64
}

// ScanLog represents a log entry for a scan.
type ScanLog struct {
	CreatedAt time.Time
	LogLevel  string
	Message   string
	Scanner   sql.NullString
	ID        int64
	ScanID    int64
}

// ScanProgress represents real-time progress for a scanner.
type ScanProgress struct {
	UpdatedAt       time.Time
	Scanner         string
	Status          string
	CurrentStep     sql.NullString
	ErrorMessage    sql.NullString
	ID              int64
	ScanID          int64
	ProgressPercent int
}
