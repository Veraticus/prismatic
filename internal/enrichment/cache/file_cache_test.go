package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joshsymonds/prismatic/internal/enrichment"
)

func TestNewFileCache(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cache, err := NewFileCache(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	if cache.basePath != tmpDir {
		t.Errorf("Expected base path %s, got %s", tmpDir, cache.basePath)
	}

	// Check that stats file was created
	statsPath := filepath.Join(tmpDir, "stats.json")
	if _, err := os.Stat(statsPath); os.IsNotExist(err) {
		t.Error("Expected stats.json to be created")
	}
}

func TestFileCache_SetAndGet(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cache, err := NewFileCache(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	ctx := context.Background()

	// Create test enrichment
	testEnrichment := &enrichment.FindingEnrichment{
		FindingID:  "test-finding-123",
		EnrichedAt: time.Now(),
		Analysis: enrichment.Analysis{
			BusinessImpact:    "Test business impact",
			PriorityReasoning: "Test priority reasoning",
			TechnicalDetails:  "Test technical details",
			PriorityScore:     8.5,
		},
		Remediation: enrichment.Remediation{
			Immediate:          []string{"Do this immediately"},
			ShortTerm:          []string{"Do this soon"},
			LongTerm:           []string{"Do this eventually"},
			EstimatedEffort:    "2 hours",
			AutomationPossible: true,
		},
		LLMModel:   "test-model",
		TokensUsed: 300,
		Context: map[string]interface{}{
			"test": "context",
		},
	}

	// Set in cache
	err = cache.Set(ctx, testEnrichment, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to set cache entry: %v", err)
	}

	// Get from cache
	retrieved, err := cache.Get(ctx, testEnrichment.FindingID)
	if err != nil {
		t.Fatalf("Failed to get cache entry: %v", err)
	}

	if retrieved.FindingID != testEnrichment.FindingID {
		t.Errorf("Expected finding ID %s, got %s", testEnrichment.FindingID, retrieved.FindingID)
	}

	if retrieved.Analysis.BusinessImpact != testEnrichment.Analysis.BusinessImpact {
		t.Errorf("Expected business impact %s, got %s", testEnrichment.Analysis.BusinessImpact, retrieved.Analysis.BusinessImpact)
	}

	// Test cache miss
	_, err = cache.Get(ctx, "non-existent-key")
	if err == nil {
		t.Error("Expected error for non-existent key")
	}
}

func TestFileCache_TTL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cache, err := NewFileCache(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	ctx := context.Background()

	testEnrichment := &enrichment.FindingEnrichment{
		FindingID: "ttl-test",
	}

	// Set with very short TTL
	err = cache.Set(ctx, testEnrichment, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to set cache entry: %v", err)
	}

	// Should be retrievable immediately
	_, err = cache.Get(ctx, "ttl-test")
	if err != nil {
		t.Error("Expected to retrieve entry immediately after setting")
	}

	// Wait for TTL to expire
	time.Sleep(200 * time.Millisecond)

	// Should now be expired
	_, err = cache.Get(ctx, "ttl-test")
	if err == nil {
		t.Error("Expected error for expired entry")
	}
}

func TestFileCache_Delete(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cache, err := NewFileCache(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	ctx := context.Background()

	testEnrichment := &enrichment.FindingEnrichment{
		FindingID: "delete-test",
	}

	// Set entry
	err = cache.Set(ctx, testEnrichment, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to set cache entry: %v", err)
	}

	// Verify it exists
	_, err = cache.Get(ctx, "delete-test")
	if err != nil {
		t.Error("Entry should exist before deletion")
	}

	// Delete entry
	err = cache.Delete(ctx, "delete-test")
	if err != nil {
		t.Fatalf("Failed to delete cache entry: %v", err)
	}

	// Verify it's gone
	_, err = cache.Get(ctx, "delete-test")
	if err == nil {
		t.Error("Expected error after deletion")
	}

	// Delete non-existent entry should not error
	err = cache.Delete(ctx, "non-existent")
	if err != nil {
		t.Error("Delete of non-existent entry should not error")
	}
}

func TestFileCache_Clear(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cache, err := NewFileCache(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	ctx := context.Background()

	// Add multiple entries
	for i := 0; i < 5; i++ {
		findingEnrichment := &enrichment.FindingEnrichment{
			FindingID: fmt.Sprintf("finding-%d", i),
		}
		if err := cache.Set(ctx, findingEnrichment, 1*time.Hour); err != nil {
			t.Fatalf("Failed to set entry %d: %v", i, err)
		}
	}

	// Verify entries exist
	for i := 0; i < 5; i++ {
		findingID := fmt.Sprintf("finding-%d", i)
		if _, err := cache.Get(ctx, findingID); err != nil {
			t.Errorf("Entry %s should exist before clear", findingID)
		}
	}

	// Clear cache
	err = cache.Clear(ctx)
	if err != nil {
		t.Fatalf("Failed to clear cache: %v", err)
	}

	// Verify all entries are gone
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("key-%d", i)
		if _, err := cache.Get(ctx, key); err == nil {
			t.Errorf("Entry %s should not exist after clear", key)
		}
	}

	// Stats should be reset
	stats, err := cache.Stats(ctx)
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}

	if stats.TotalEntries != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", stats.TotalEntries)
	}
}

func TestFileCache_Stats(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cache, err := NewFileCache(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	ctx := context.Background()

	// Initial stats
	stats, err := cache.Stats(ctx)
	if err != nil {
		t.Fatalf("Failed to get initial stats: %v", err)
	}

	if stats.TotalHits != 0 || stats.TotalMisses != 0 {
		t.Error("Expected initial stats to be zero")
	}

	// Add some entries and perform operations
	testEnrichment := &enrichment.FindingEnrichment{
		FindingID:  "stats-test",
		TokensUsed: 1500,
		LLMModel:   "test-model",
		Analysis: enrichment.Analysis{
			BusinessImpact: "Test impact",
			PriorityScore:  5.0,
		},
	}

	// Set entry
	err = cache.Set(ctx, testEnrichment, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to set cache entry: %v", err)
	}

	// Hit
	_, err = cache.Get(ctx, "stats-test")
	if err != nil {
		t.Error("Expected cache hit")
	}

	// Miss
	_, err = cache.Get(ctx, "missing-key")
	if err == nil {
		t.Error("Expected cache miss")
	}

	// Get updated stats
	stats, err = cache.Stats(ctx)
	if err != nil {
		t.Fatalf("Failed to get updated stats: %v", err)
	}

	if stats.TotalHits != 1 {
		t.Errorf("Expected 1 hit, got %d", stats.TotalHits)
	}

	if stats.TotalMisses != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.TotalMisses)
	}

	if stats.TotalEntries != 1 {
		t.Errorf("Expected 1 entry, got %d", stats.TotalEntries)
	}

	// Hit rate should be 0.5 (1 hit, 1 miss)
	expectedHitRate := 0.5
	if stats.HitRate != expectedHitRate {
		t.Errorf("Expected hit rate %f, got %f", expectedHitRate, stats.HitRate)
	}

	// Tokens saved should be 1500 (prompt + response)
	if stats.TokensSaved != 1500 {
		t.Errorf("Expected 1500 tokens saved, got %d", stats.TokensSaved)
	}
}

func TestFileCache_ConcurrentAccess(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cache, err := NewFileCache(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	ctx := context.Background()
	done := make(chan bool, 20)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(id int) {
			findingEnrichment := &enrichment.FindingEnrichment{
				FindingID: fmt.Sprintf("concurrent-%d", id),
			}

			if err := cache.Set(ctx, findingEnrichment, 1*time.Hour); err != nil {
				t.Errorf("Failed to set concurrent entry %d: %v", id, err)
			}

			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func(id int) {
			findingID := fmt.Sprintf("concurrent-%d", id)

			// Give writes a chance to complete
			time.Sleep(10 * time.Millisecond)

			if _, err := cache.Get(ctx, findingID); err != nil {
				// It's ok if not found, as write might not have completed
				t.Logf("Concurrent read %d: %v", id, err)
			}

			done <- true
		}(i)
	}

	// Wait for all operations to complete
	for i := 0; i < 20; i++ {
		<-done
	}

	// Verify final state
	stats, err := cache.Stats(ctx)
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}

	t.Logf("Final stats: entries=%d, hits=%d, misses=%d",
		stats.TotalEntries, stats.TotalHits, stats.TotalMisses)
}

func TestFileCache_InvalidPath(t *testing.T) {
	// Test with invalid path
	_, err := NewFileCache("/invalid/path/that/does/not/exist")
	if err == nil {
		t.Error("Expected error for invalid path")
	}
}

func TestCacheEntry_JSON(t *testing.T) {
	entry := &cacheEntry{
		Enrichment: enrichment.FindingEnrichment{
			FindingID: "test-123",
			Analysis: enrichment.Analysis{
				BusinessImpact: "Test summary",
				PriorityScore:  5.0,
			},
		},
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Marshal to JSON
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Failed to marshal cache entry: %v", err)
	}

	// Unmarshal back
	var decoded cacheEntry
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal cache entry: %v", err)
	}

	if decoded.Enrichment.FindingID != entry.Enrichment.FindingID {
		t.Errorf("Expected finding ID %s, got %s",
			entry.Enrichment.FindingID, decoded.Enrichment.FindingID)
	}
}

func TestFileCache_CleanupExpired(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cache, err := NewFileCache(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	ctx := context.Background()

	// Add entry with short TTL
	shortTTLEnrichment := &enrichment.FindingEnrichment{
		FindingID: "short-ttl",
	}
	err = cache.Set(ctx, shortTTLEnrichment, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to set short TTL entry: %v", err)
	}

	// Add entry with long TTL
	longTTLEnrichment := &enrichment.FindingEnrichment{
		FindingID: "long-ttl",
	}
	err = cache.Set(ctx, longTTLEnrichment, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to set long TTL entry: %v", err)
	}

	// Wait for short TTL to expire
	time.Sleep(10 * time.Millisecond)

	// Trigger cleanup by trying to get expired entry
	_, _ = cache.Get(ctx, "short-ttl-key")

	// Verify short TTL entry is gone
	_, err = cache.Get(ctx, "short-ttl-key")
	if err == nil {
		t.Error("Expected short TTL entry to be expired")
	}

	// Verify long TTL entry still exists
	_, err = cache.Get(ctx, "long-ttl-key")
	if err != nil {
		t.Error("Expected long TTL entry to still exist")
	}
}
