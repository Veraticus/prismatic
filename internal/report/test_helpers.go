package report

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/stretchr/testify/require"
)

// convertSeverityToDatabase converts model severity to database severity format.
func convertSeverityToDatabase(severity string) database.Severity {
	switch severity {
	case "critical":
		return database.SeverityCritical
	case "high":
		return database.SeverityHigh
	case "medium":
		return database.SeverityMedium
	case "low":
		return database.SeverityLow
	case "info":
		return database.SeverityInfo
	default:
		return database.SeverityInfo
	}
}

// saveFindingsToDatabase is a helper function to save findings to the database.
func saveFindingsToDatabase(t *testing.T, db *database.DB, scanID int64, metadata *models.ScanMetadata) {
	t.Helper()
	ctx := context.Background()
	var dbFindings []*database.Finding

	for _, result := range metadata.Results {
		for _, finding := range result.Findings {
			// Convert technical details to JSON if present
			var techDetails []byte
			// Build technical details including original finding ID
			techData := make(map[string]any)
			techData["original_id"] = finding.ID
			for k, v := range finding.Metadata {
				techData[k] = v
			}
			if techJSON, err := json.Marshal(techData); err == nil {
				techDetails = techJSON
			}

			dbFindings = append(dbFindings, &database.Finding{
				ScanID:           scanID,
				Scanner:          finding.Scanner,
				Severity:         convertSeverityToDatabase(finding.Severity),
				Title:            finding.Title,
				Description:      finding.Description,
				Resource:         finding.Resource,
				TechnicalDetails: techDetails,
			})
		}
	}

	if len(dbFindings) > 0 {
		err := db.BatchInsertFindings(ctx, scanID, dbFindings)
		require.NoError(t, err)
	}
}
