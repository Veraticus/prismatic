package models

// Severity levels as constants for type safety and consistency.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
	SeverityUnknown  = "unknown"
)

// ValidSeverities returns all valid severity levels for validation.
func ValidSeverities() []string {
	return []string{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
		SeverityUnknown,
	}
}

// IsValidSeverity checks if a severity level is valid.
func IsValidSeverity(severity string) bool {
	switch severity {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo, SeverityUnknown:
		return true
	default:
		return false
	}
}
