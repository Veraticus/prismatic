package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSetCompletedWithFindings(t *testing.T) {
	tests := []struct {
		findingCounts map[string]int
		name          string
		expectedMsg   string
		totalFindings int
	}{
		{
			name:          "no findings",
			totalFindings: 0,
			findingCounts: map[string]int{},
			expectedMsg:   "No findings",
		},
		{
			name:          "single finding",
			totalFindings: 1,
			findingCounts: map[string]int{"high": 1},
			expectedMsg:   "1 finding",
		},
		{
			name:          "multiple findings",
			totalFindings: 5,
			findingCounts: map[string]int{"critical": 1, "high": 2, "medium": 2},
			expectedMsg:   "5 findings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := NewScannerStatus("test-scanner")
			status.SetCompletedWithFindings(tt.totalFindings, tt.findingCounts)

			assert.Equal(t, StatusSuccess, status.Status)
			assert.Equal(t, 100, status.Progress)
			assert.Equal(t, tt.totalFindings, status.TotalFindings)
			assert.Equal(t, tt.findingCounts, status.FindingCounts)
			assert.Equal(t, tt.expectedMsg, status.Message)
			assert.NotEmpty(t, status.ElapsedTime)
		})
	}
}

func TestElapsedTimeFormatting(t *testing.T) {
	status := NewScannerStatus("test-scanner")

	// Test sub-minute formatting
	status.StartTime = time.Now()
	status.updateElapsedTime()
	assert.Contains(t, status.ElapsedTime, "s")
	assert.NotContains(t, status.ElapsedTime, "m")

	// Test over-minute formatting
	status.StartTime = time.Now().Add(-90 * time.Second)
	status.updateElapsedTime()
	assert.Contains(t, status.ElapsedTime, "m")
	assert.Contains(t, status.ElapsedTime, "s")
}
