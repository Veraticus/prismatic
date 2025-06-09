package models

import (
	"fmt"
	"time"
)

// ScannerStatus represents the current state of a scanner.
type ScannerStatus struct {
	StartTime   time.Time `json:"start_time"`
	Scanner     string    `json:"scanner"`
	Status      string    `json:"status"`
	Message     string    `json:"message,omitempty"`
	ElapsedTime string    `json:"elapsed_time,omitempty"`
	Progress    int       `json:"progress,omitempty"`
	Total       int       `json:"total,omitempty"`
	Current     int       `json:"current,omitempty"`
}

// Scanner status constants.
const (
	StatusPending  = "pending"
	StatusStarting = "starting"
	StatusRunning  = "running"
	StatusSuccess  = "success"
	StatusFailed   = "failed"
	StatusSkipped  = "skipped"
)

// NewScannerStatus creates a new scanner status.
func NewScannerStatus(scanner string) *ScannerStatus {
	return &ScannerStatus{
		Scanner:   scanner,
		Status:    StatusPending,
		StartTime: time.Now(),
	}
}

// SetRunning updates the status to running with optional message.
func (s *ScannerStatus) SetRunning(message string) {
	s.Status = StatusRunning
	s.Message = message
	s.updateElapsedTime()
}

// SetProgress updates the progress information.
func (s *ScannerStatus) SetProgress(current, total int) {
	s.Current = current
	s.Total = total
	if total > 0 {
		s.Progress = (current * 100) / total
	}
	s.updateElapsedTime()
}

// SetCompleted marks the scanner as completed.
func (s *ScannerStatus) SetCompleted() {
	s.Status = StatusSuccess
	s.Progress = 100
	s.updateElapsedTime()
}

// SetFailed marks the scanner as failed.
func (s *ScannerStatus) SetFailed(err error) {
	s.Status = StatusFailed
	if err != nil {
		s.Message = err.Error()
	}
	s.updateElapsedTime()
}

// updateElapsedTime updates the elapsed time string.
func (s *ScannerStatus) updateElapsedTime() {
	elapsed := time.Since(s.StartTime)
	if elapsed < time.Minute {
		s.ElapsedTime = elapsed.Round(time.Second).String()
	} else {
		minutes := int(elapsed.Minutes())
		seconds := int(elapsed.Seconds()) % 60
		s.ElapsedTime = fmt.Sprintf("%dm%ds", minutes, seconds)
	}
}
