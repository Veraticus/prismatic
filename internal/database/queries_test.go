package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestCreateScan(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	tests := []struct {
		scan    *Scan
		name    string
		wantErr bool
	}{
		{
			name: "basic scan",
			scan: &Scan{
				AWSProfile: sql.NullString{String: "default", Valid: true},
				AWSRegions: []string{"us-east-1", "us-west-2"},
				Scanners:   ScannerProwler | ScannerTrivy,
				Status:     ScanStatusRunning,
			},
		},
		{
			name: "scan with kube context",
			scan: &Scan{
				KubeContext: sql.NullString{String: "minikube", Valid: true},
				Scanners:    ScannerKubescape,
				Status:      ScanStatusRunning,
			},
		},
		{
			name: "scan with no regions",
			scan: &Scan{
				AWSProfile: sql.NullString{String: "prod", Valid: true},
				Scanners:   ScannerProwler,
				Status:     ScanStatusRunning,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := db.CreateScan(ctx, tt.scan)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateScan() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && id <= 0 {
				t.Errorf("CreateScan() returned invalid ID: %d", id)
			}
		})
	}
}

func TestUpdateScanStatus(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Create a scan
	scan := &Scan{
		AWSProfile: sql.NullString{String: "test", Valid: true},
		Scanners:   ScannerProwler,
		Status:     ScanStatusRunning,
	}
	scanID, err := db.CreateScan(ctx, scan)
	if err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	tests := []struct {
		errorDetails *string
		name         string
		status       ScanStatus
		scanID       int64
		wantErr      bool
	}{
		{
			name:    "update to completed",
			scanID:  scanID,
			status:  ScanStatusCompleted,
			wantErr: false,
		},
		{
			name:         "update to failed with error",
			scanID:       scanID,
			status:       ScanStatusFailed,
			errorDetails: stringPtr("Connection timeout"),
			wantErr:      false,
		},
		{
			name:    "update non-existent scan",
			scanID:  99999,
			status:  ScanStatusCompleted,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updateErr := db.UpdateScanStatus(ctx, tt.scanID, tt.status, tt.errorDetails)
			if (updateErr != nil) != tt.wantErr {
				t.Errorf("UpdateScanStatus() error = %v, wantErr %v", updateErr, tt.wantErr)
			}
		})
	}

	// Verify completed_at is set
	updatedScan, err := db.GetScan(ctx, scanID)
	if err != nil {
		t.Fatalf("Failed to get updated scan: %v", err)
	}
	if !updatedScan.CompletedAt.Valid {
		t.Error("Expected completed_at to be set")
	}
}

func TestBatchInsertFindings(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Create a scan
	scanID, err := db.CreateScan(ctx, &Scan{
		Scanners: ScannerProwler,
		Status:   ScanStatusRunning,
	})
	if err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	// Test batch insert with various sizes
	tests := []struct {
		name    string
		count   int
		wantErr bool
	}{
		{"empty batch", 0, false},
		{"small batch", 10, false},
		{"medium batch", 500, false},
		{"large batch", 1500, false}, // Tests chunking
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := make([]*Finding, tt.count)
			for i := 0; i < tt.count; i++ {
				findings[i] = &Finding{
					Scanner:          ScannerNameProwler,
					Severity:         Severity([]string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}[i%4]),
					Title:            fmt.Sprintf("Finding %d", i),
					Description:      fmt.Sprintf("Description for finding %d", i),
					Resource:         fmt.Sprintf("arn:aws:s3:::bucket-%d", i),
					TechnicalDetails: json.RawMessage(fmt.Sprintf(`{"index": %d}`, i)),
				}
			}

			err := db.BatchInsertFindings(ctx, scanID, findings)
			if (err != nil) != tt.wantErr {
				t.Errorf("BatchInsertFindings() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil {
				// Verify count
				var count int
				err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE scan_id = ?", scanID).Scan(&count)
				if err != nil {
					t.Fatalf("Failed to count findings: %v", err)
				}
				if count != tt.count {
					t.Errorf("Expected %d findings, got %d", tt.count, count)
				}
			}

			// Clean up for next test
			if _, err := db.ExecContext(ctx, "DELETE FROM findings WHERE scan_id = ?", scanID); err != nil {
				t.Errorf("Failed to clean up findings: %v", err)
			}
		})
	}
}

func TestGetScan(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Create test scan
	originalScan := &Scan{
		AWSProfile: sql.NullString{String: "prod", Valid: true},
		AWSRegions: []string{"us-east-1", "eu-west-1"},
		Scanners:   ScannerProwler | ScannerTrivy,
		Status:     ScanStatusRunning,
	}
	scanID, err := db.CreateScan(ctx, originalScan)
	if err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	// Test getting existing scan
	scan, err := db.GetScan(ctx, scanID)
	if err != nil {
		t.Fatalf("GetScan() error = %v", err)
	}

	// Verify fields
	if scan.ID != scanID {
		t.Errorf("Expected ID %d, got %d", scanID, scan.ID)
	}
	if scan.AWSProfile.String != originalScan.AWSProfile.String {
		t.Errorf("Expected AWSProfile %s, got %s", originalScan.AWSProfile.String, scan.AWSProfile.String)
	}
	if len(scan.AWSRegions) != len(originalScan.AWSRegions) {
		t.Errorf("Expected %d regions, got %d", len(originalScan.AWSRegions), len(scan.AWSRegions))
	}
	if scan.Scanners != originalScan.Scanners {
		t.Errorf("Expected scanners %v, got %v", originalScan.Scanners, scan.Scanners)
	}

	// Test getting non-existent scan
	_, err = db.GetScan(ctx, 99999)
	if err == nil {
		t.Error("Expected error for non-existent scan")
	}
}

func TestListScans(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Create test scans
	for i := 0; i < 5; i++ {
		status := ScanStatusRunning
		if i%2 == 0 {
			status = ScanStatusCompleted
		}

		_, err := db.CreateScan(ctx, &Scan{
			AWSProfile: sql.NullString{String: fmt.Sprintf("profile-%d", i%2), Valid: true},
			Scanners:   ScannerProwler,
			Status:     status,
		})
		if err != nil {
			t.Fatalf("Failed to create scan %d: %v", i, err)
		}

		// Add small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
	}

	tests := []struct {
		name          string
		filter        ScanFilter
		expectedCount int
	}{
		{
			name:          "no filter",
			filter:        ScanFilter{},
			expectedCount: 5,
		},
		{
			name:          "filter by status",
			filter:        ScanFilter{Status: &[]ScanStatus{ScanStatusCompleted}[0]},
			expectedCount: 3,
		},
		{
			name:          "filter by profile",
			filter:        ScanFilter{AWSProfile: stringPtr("profile-0")},
			expectedCount: 3,
		},
		{
			name:          "with pagination",
			filter:        ScanFilter{Limit: 2, Offset: 1},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scans, err := db.ListScans(ctx, tt.filter)
			if err != nil {
				t.Fatalf("ListScans() error = %v", err)
			}
			if len(scans) != tt.expectedCount {
				t.Errorf("Expected %d scans, got %d", tt.expectedCount, len(scans))
			}

			// Verify ordering (most recent first)
			for i := 1; i < len(scans); i++ {
				if scans[i-1].StartedAt.Before(scans[i].StartedAt) {
					t.Error("Scans not ordered by started_at DESC")
				}
			}
		})
	}
}

func TestGetFindings(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Create scan and findings
	scanID, err := db.CreateScan(ctx, &Scan{
		Scanners: ScannerProwler | ScannerTrivy,
		Status:   ScanStatusRunning,
	})
	if err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	// Insert test findings
	findings := []*Finding{
		{Scanner: ScannerNameProwler, Severity: SeverityCritical, Title: "Critical Finding", Resource: "arn:aws:s3:::bucket1"},
		{Scanner: ScannerNameProwler, Severity: SeverityHigh, Title: "High Finding", Resource: "arn:aws:ec2:::instance1"},
		{Scanner: ScannerNameTrivy, Severity: SeverityMedium, Title: "Medium Finding", Resource: "nginx:latest"},
		{Scanner: ScannerNameTrivy, Severity: SeverityLow, Title: "Low Finding", Resource: "alpine:3.14"},
		{Scanner: ScannerNameTrivy, Severity: SeverityInfo, Title: "Info Finding", Resource: "alpine:3.14"},
	}

	if insertErr := db.BatchInsertFindings(ctx, scanID, findings); insertErr != nil {
		t.Fatalf("Failed to insert findings: %v", insertErr)
	}

	tests := []struct {
		name          string
		filter        FindingFilter
		expectedCount int
	}{
		{
			name:          "no filter",
			filter:        FindingFilter{},
			expectedCount: 5,
		},
		{
			name:          "filter by scanner",
			filter:        FindingFilter{Scanner: stringPtr(ScannerNameProwler)},
			expectedCount: 2,
		},
		{
			name:          "filter by severity",
			filter:        FindingFilter{Severity: &[]Severity{SeverityCritical}[0]},
			expectedCount: 1,
		},
		{
			name:          "filter by resource",
			filter:        FindingFilter{Resource: stringPtr("alpine")},
			expectedCount: 2,
		},
		{
			name:          "with pagination",
			filter:        FindingFilter{Limit: 3, Offset: 1},
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := db.GetFindings(ctx, scanID, tt.filter)
			if err != nil {
				t.Fatalf("GetFindings() error = %v", err)
			}
			if len(results) != tt.expectedCount {
				t.Errorf("Expected %d findings, got %d", tt.expectedCount, len(results))
			}

			// Verify ordering by severity
			if len(results) > 1 && tt.filter.Severity == nil {
				severityOrder := map[Severity]int{
					SeverityCritical: 1,
					SeverityHigh:     2,
					SeverityMedium:   3,
					SeverityLow:      4,
					SeverityInfo:     5,
				}

				for i := 1; i < len(results); i++ {
					if severityOrder[results[i-1].Severity] > severityOrder[results[i].Severity] {
						t.Error("Findings not ordered by severity")
					}
				}
			}
		})
	}
}

func TestGetFindingCounts(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Create scan
	scanID, err := db.CreateScan(ctx, &Scan{
		Scanners: ScannerProwler,
		Status:   ScanStatusRunning,
	})
	if err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	// Insert findings with known counts
	findings := []*Finding{
		{Scanner: ScannerNameProwler, Severity: SeverityCritical, Title: "Finding 1"},
		{Scanner: ScannerNameProwler, Severity: SeverityCritical, Title: "Finding 2"},
		{Scanner: ScannerNameProwler, Severity: SeverityHigh, Title: "Finding 3"},
		{Scanner: ScannerNameProwler, Severity: SeverityMedium, Title: "Finding 4"},
		{Scanner: ScannerNameProwler, Severity: SeverityMedium, Title: "Finding 5"},
		{Scanner: ScannerNameProwler, Severity: SeverityMedium, Title: "Finding 6"},
		{Scanner: ScannerNameProwler, Severity: SeverityLow, Title: "Finding 7"},
		{Scanner: ScannerNameProwler, Severity: SeverityInfo, Title: "Finding 8"},
	}

	if insertErr := db.BatchInsertFindings(ctx, scanID, findings); insertErr != nil {
		t.Fatalf("Failed to insert findings: %v", insertErr)
	}

	counts, err := db.GetFindingCounts(ctx, scanID)
	if err != nil {
		t.Fatalf("GetFindingCounts() error = %v", err)
	}

	expected := &FindingCounts{
		Critical: 2,
		High:     1,
		Medium:   3,
		Low:      1,
		Info:     1,
		Total:    8,
	}

	if *counts != *expected {
		t.Errorf("Expected counts %+v, got %+v", expected, counts)
	}

	// Test with scan that has no findings
	emptyScanID, _ := db.CreateScan(ctx, &Scan{
		Scanners: ScannerProwler,
		Status:   ScanStatusRunning,
	})

	emptyCounts, err := db.GetFindingCounts(ctx, emptyScanID)
	if err != nil {
		t.Fatalf("GetFindingCounts() error for empty scan = %v", err)
	}

	if emptyCounts.Total != 0 {
		t.Errorf("Expected 0 total for empty scan, got %d", emptyCounts.Total)
	}
}

func TestSuppressions(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Create scan and finding
	scanID, _ := db.CreateScan(ctx, &Scan{
		Scanners: ScannerProwler,
		Status:   ScanStatusRunning,
	})

	findings := []*Finding{{
		Scanner:  ScannerNameProwler,
		Severity: SeverityHigh,
		Title:    "Test Finding",
	}}

	if insertErr := db.BatchInsertFindings(ctx, scanID, findings); insertErr != nil {
		t.Fatalf("Failed to insert findings: %v", insertErr)
	}

	// Get the finding ID
	results, _ := db.GetFindings(ctx, scanID, FindingFilter{})
	if len(results) == 0 {
		t.Fatal("No findings found")
	}
	findingID := results[0].ID

	// Test creating suppression
	suppression := &Suppression{
		FindingID:    findingID,
		Reason:       "False positive - development resource",
		SuppressedBy: "admin@example.com",
	}

	err = db.CreateSuppression(ctx, suppression)
	if err != nil {
		t.Fatalf("CreateSuppression() error = %v", err)
	}

	if suppression.ID <= 0 {
		t.Error("Expected suppression ID to be set")
	}

	// Test getting suppressions
	suppressions, err := db.GetSuppressions(ctx, findingID)
	if err != nil {
		t.Fatalf("GetSuppressions() error = %v", err)
	}

	if len(suppressions) != 1 {
		t.Errorf("Expected 1 suppression, got %d", len(suppressions))
	}

	if suppressions[0].Reason != suppression.Reason {
		t.Errorf("Expected reason %s, got %s", suppression.Reason, suppressions[0].Reason)
	}
}

func TestDeleteScan(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Create scan with findings and suppressions
	scanID, _ := db.CreateScan(ctx, &Scan{
		Scanners: ScannerProwler,
		Status:   ScanStatusCompleted,
	})

	// Add findings
	findings := []*Finding{
		{Scanner: ScannerNameProwler, Severity: SeverityHigh, Title: "Finding 1"},
		{Scanner: ScannerNameProwler, Severity: SeverityMedium, Title: "Finding 2"},
	}
	if insertErr := db.BatchInsertFindings(ctx, scanID, findings); insertErr != nil {
		t.Fatalf("Failed to insert findings: %v", insertErr)
	}

	// Add suppression to one finding
	results, _ := db.GetFindings(ctx, scanID, FindingFilter{})
	if len(results) > 0 {
		if suppressErr := db.CreateSuppression(ctx, &Suppression{
			FindingID:    results[0].ID,
			Reason:       "Test suppression",
			SuppressedBy: "test@example.com",
		}); suppressErr != nil {
			t.Errorf("Failed to create suppression: %v", suppressErr)
		}
	}

	// Delete the scan
	err = db.DeleteScan(ctx, scanID)
	if err != nil {
		t.Fatalf("DeleteScan() error = %v", err)
	}

	// Verify scan is deleted
	_, err = db.GetScan(ctx, scanID)
	if err == nil {
		t.Error("Expected error when getting deleted scan")
	}

	// Verify findings are deleted
	remainingFindings, _ := db.GetFindings(ctx, scanID, FindingFilter{})
	if len(remainingFindings) != 0 {
		t.Errorf("Expected 0 findings after deletion, got %d", len(remainingFindings))
	}

	// Try deleting non-existent scan
	err = db.DeleteScan(ctx, 99999)
	if err == nil {
		t.Error("Expected error when deleting non-existent scan")
	}
}

func TestGetScannerStats(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Create scan
	scanID, _ := db.CreateScan(ctx, &Scan{
		Scanners: ScannerProwler | ScannerTrivy,
		Status:   ScanStatusRunning,
	})

	// Insert findings for different scanners
	findings := []*Finding{
		// Prowler findings
		{Scanner: ScannerNameProwler, Severity: SeverityCritical, Title: "P1"},
		{Scanner: ScannerNameProwler, Severity: SeverityCritical, Title: "P2"},
		{Scanner: ScannerNameProwler, Severity: SeverityHigh, Title: "P3"},
		{Scanner: ScannerNameProwler, Severity: SeverityMedium, Title: "P4"},
		// Trivy findings
		{Scanner: ScannerNameTrivy, Severity: SeverityHigh, Title: "T1"},
		{Scanner: ScannerNameTrivy, Severity: SeverityMedium, Title: "T2"},
		{Scanner: ScannerNameTrivy, Severity: SeverityMedium, Title: "T3"},
		{Scanner: ScannerNameTrivy, Severity: SeverityLow, Title: "T4"},
		{Scanner: ScannerNameTrivy, Severity: SeverityInfo, Title: "T5"},
	}

	if insertErr := db.BatchInsertFindings(ctx, scanID, findings); insertErr != nil {
		t.Fatalf("Failed to insert findings: %v", insertErr)
	}

	stats, err := db.GetScannerStats(ctx, scanID)
	if err != nil {
		t.Fatalf("GetScannerStats() error = %v", err)
	}

	// Verify Prowler stats
	prowlerStats, ok := stats[ScannerNameProwler]
	if !ok {
		t.Error("Missing Prowler stats")
	} else if prowlerStats.Critical != 2 || prowlerStats.High != 1 || prowlerStats.Medium != 1 || prowlerStats.Total != 4 {
		t.Errorf("Incorrect Prowler stats: %+v", prowlerStats)
	}

	// Verify Trivy stats
	trivyStats, ok := stats[ScannerNameTrivy]
	if !ok {
		t.Error("Missing Trivy stats")
	} else if trivyStats.High != 1 || trivyStats.Medium != 2 || trivyStats.Low != 1 || trivyStats.Info != 1 || trivyStats.Total != 5 {
		t.Errorf("Incorrect Trivy stats: %+v", trivyStats)
	}
}

func TestSearchFindings(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Create scan
	scanID, _ := db.CreateScan(ctx, &Scan{
		Scanners: ScannerProwler,
		Status:   ScanStatusRunning,
	})

	// Insert findings with searchable content
	findings := []*Finding{
		{Scanner: ScannerNameProwler, Severity: SeverityCritical, Title: "S3 bucket public access", Description: "Bucket allows public read", Resource: "arn:aws:s3:::public-bucket"},
		{Scanner: ScannerNameProwler, Severity: SeverityHigh, Title: "EC2 instance without encryption", Description: "Instance storage not encrypted", Resource: "arn:aws:ec2:::instance-123"},
		{Scanner: ScannerNameProwler, Severity: SeverityMedium, Title: "RDS backup not enabled", Description: "Database backups are disabled", Resource: "arn:aws:rds:::db-prod"},
		{Scanner: ScannerNameProwler, Severity: SeverityLow, Title: "CloudTrail not configured", Description: "Logging is not enabled", Resource: "arn:aws:cloudtrail:::trail-main"},
	}

	if insertErr := db.BatchInsertFindings(ctx, scanID, findings); insertErr != nil {
		t.Fatalf("Failed to insert findings: %v", insertErr)
	}

	tests := []struct {
		name          string
		searchTerm    string
		expectedCount int
	}{
		{"search title", "bucket", 1},
		{"search description", "encrypted", 1},
		{"search resource", "rds", 1},
		{"search multiple matches", "not", 3}, // matches "not encrypted", "not enabled", "not configured"
		{"no matches", "kubernetes", 0},
		{"case insensitive", "BUCKET", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := db.SearchFindings(ctx, scanID, tt.searchTerm, 10)
			if err != nil {
				t.Fatalf("SearchFindings() error = %v", err)
			}
			if len(results) != tt.expectedCount {
				t.Errorf("Expected %d results for '%s', got %d", tt.expectedCount, tt.searchTerm, len(results))
			}
		})
	}
}

func TestConcurrentOperations(t *testing.T) {
	// Test concurrent reads instead of writes for SQLite compatibility
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// First, create some test data sequentially
	var scanIDs []int64
	for i := 0; i < 5; i++ {
		scan := &Scan{
			AWSProfile: sql.NullString{String: fmt.Sprintf("profile-%d", i), Valid: true},
			Scanners:   ScannerProwler,
			Status:     ScanStatusRunning,
		}

		id, err := db.CreateScan(ctx, scan)
		if err != nil {
			t.Fatalf("Failed to create scan %d: %v", i, err)
		}

		// Insert findings
		findings := make([]*Finding, 20)
		for j := 0; j < 20; j++ {
			findings[j] = &Finding{
				Scanner:     ScannerNameProwler,
				Severity:    SeverityMedium,
				Title:       fmt.Sprintf("Finding %d-%d", i, j),
				Description: "Test finding",
			}
		}

		if err := db.BatchInsertFindings(ctx, id, findings); err != nil {
			t.Fatalf("Failed to insert findings for scan %d: %v", i, err)
		}

		scanIDs = append(scanIDs, id)
	}

	// Now test concurrent reads
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer func() { done <- true }()

			// Read operations that should work concurrently
			scanID := scanIDs[idx%len(scanIDs)]

			// Get scan
			_, err := db.GetScan(ctx, scanID)
			if err != nil {
				errors <- fmt.Errorf("getting scan: %w", err)
				return
			}

			// Get findings
			_, err = db.GetFindings(ctx, scanID, FindingFilter{Limit: 10})
			if err != nil {
				errors <- fmt.Errorf("getting findings: %w", err)
				return
			}

			// Get counts
			_, err = db.GetFindingCounts(ctx, scanID)
			if err != nil {
				errors <- fmt.Errorf("getting counts: %w", err)
				return
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Check for errors
	close(errors)
	for err := range errors {
		t.Errorf("Concurrent read error: %v", err)
	}
}

// Helper function to create string pointers.
func stringPtr(s string) *string {
	return &s
}
