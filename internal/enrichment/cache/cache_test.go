package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/joshsymonds/prismatic/internal/enrichment"
)

func TestDefaultKeyGenerator(t *testing.T) {
	gen := &DefaultKeyGenerator{}

	tests := []struct {
		name      string
		findingID string
		context   map[string]any
		expected  string
	}{
		{
			name:      "Simple finding ID",
			findingID: "finding-123",
			context:   nil,
			expected:  "finding-123",
		},
		{
			name:      "Finding ID with context",
			findingID: "finding-456",
			context:   map[string]any{"env": "prod"},
			expected:  "finding-456", // Current implementation ignores context
		},
		{
			name:      "Empty finding ID",
			findingID: "",
			context:   nil,
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := gen.GenerateKey(tt.findingID, tt.context)
			if key != tt.expected {
				t.Errorf("Expected key '%s', got '%s'", tt.expected, key)
			}
		})
	}
}

func TestError(t *testing.T) {
	baseErr := fmt.Errorf("underlying error")
	cacheErr := &Error{
		Op:  "get",
		Key: "test-key",
		Err: baseErr,
	}

	expectedMsg := "cache get failed for key test-key: underlying error"
	if cacheErr.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, cacheErr.Error())
	}

	// Test Unwrap
	unwrapped := cacheErr.Unwrap()
	if unwrapped != baseErr {
		t.Error("Unwrap did not return the base error")
	}
}

func TestStats(t *testing.T) {
	stats := &Stats{
		TotalEntries: 100,
		TotalHits:    80,
		TotalMisses:  20,
		TotalSize:    1024 * 1024, // 1MB
		OldestEntry:  24 * time.Hour,
		TokensSaved:  50000,
	}

	// Calculate hit rate
	stats.HitRate = float64(stats.TotalHits) / float64(stats.TotalHits+stats.TotalMisses)

	if stats.HitRate != 0.8 {
		t.Errorf("Expected hit rate 0.8, got %f", stats.HitRate)
	}

	// Test total requests
	totalRequests := stats.TotalHits + stats.TotalMisses
	if totalRequests != 100 {
		t.Errorf("Expected 100 total requests, got %d", totalRequests)
	}

	// Test other stats fields
	if stats.TotalEntries != 100 {
		t.Errorf("Expected 100 total entries, got %d", stats.TotalEntries)
	}

	if stats.TotalSize != 1024*1024 {
		t.Errorf("Expected 1MB total size, got %d", stats.TotalSize)
	}

	if stats.OldestEntry != 24*time.Hour {
		t.Errorf("Expected oldest entry 24h, got %v", stats.OldestEntry)
	}

	if stats.TokensSaved != 50000 {
		t.Errorf("Expected 50000 tokens saved, got %d", stats.TokensSaved)
	}
}

func TestMockCacheOperations(t *testing.T) {
	ctx := context.Background()

	// Test successful cache operations
	cache := &MockCache{
		GetFunc: func(_ context.Context, findingID string) (*enrichment.FindingEnrichment, error) {
			if findingID == "test-finding" {
				return &enrichment.FindingEnrichment{
					FindingID: "test-finding",
					Analysis: enrichment.Analysis{
						BusinessImpact: "Cached enrichment",
					},
				}, nil
			}
			return nil, &Error{Op: "get", Key: findingID, Err: fmt.Errorf("not found")}
		},
		SetFunc: func(_ context.Context, e *enrichment.FindingEnrichment, _ time.Duration) error {
			if e.FindingID == "" {
				return fmt.Errorf("empty finding ID")
			}
			return nil
		},
		StatsFunc: func(_ context.Context) (*Stats, error) {
			return &Stats{
				TotalEntries: 10,
				TotalHits:    8,
				TotalMisses:  2,
				HitRate:      0.8,
			}, nil
		},
	}

	// Test Get - existing key
	foundEnrichment, err := cache.Get(ctx, "test-finding")
	if err != nil {
		t.Errorf("Expected no error for existing key, got %v", err)
	}
	if foundEnrichment.FindingID != "test-finding" {
		t.Errorf("Expected finding ID 'test-finding', got %s", foundEnrichment.FindingID)
	}

	// Test Get - missing key
	_, err = cache.Get(ctx, "missing-finding")
	if err == nil {
		t.Error("Expected error for missing key")
	}

	// Test Set
	testEnrichment := &enrichment.FindingEnrichment{
		FindingID: "new-finding",
	}
	err = cache.Set(ctx, testEnrichment, 1*time.Hour)
	if err != nil {
		t.Errorf("Expected no error for Set, got %v", err)
	}

	// Test Set with empty finding ID
	emptyIDEnrichment := &enrichment.FindingEnrichment{
		FindingID: "",
	}
	err = cache.Set(ctx, emptyIDEnrichment, 1*time.Hour)
	if err == nil {
		t.Error("Expected error for empty finding ID")
	}

	// Test Stats
	stats, err := cache.Stats(ctx)
	if err != nil {
		t.Errorf("Expected no error for GetStats, got %v", err)
	}
	if stats.HitRate != 0.8 {
		t.Errorf("Expected hit rate 0.8, got %f", stats.HitRate)
	}
}

func TestCacheTTL(t *testing.T) {
	// Test various TTL scenarios
	tests := []struct {
		name    string
		ttl     time.Duration
		age     time.Duration
		expired bool
	}{
		{
			name:    "Not expired",
			ttl:     1 * time.Hour,
			age:     30 * time.Minute,
			expired: false,
		},
		{
			name:    "Just expired",
			ttl:     1 * time.Hour,
			age:     61 * time.Minute,
			expired: true,
		},
		{
			name:    "Zero TTL (never expires)",
			ttl:     0,
			age:     365 * 24 * time.Hour,
			expired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isExpired := tt.ttl > 0 && tt.age > tt.ttl
			if isExpired != tt.expired {
				t.Errorf("Expected expired=%v for ttl=%v and age=%v", tt.expired, tt.ttl, tt.age)
			}
		})
	}
}
