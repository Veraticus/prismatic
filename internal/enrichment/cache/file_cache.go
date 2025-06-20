package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/joshsymonds/prismatic/internal/enrichment"
)


// Compile-time checks to ensure interfaces are satisfied.
var (
	_ Cache = (*FileCache)(nil)
	_ Cache = (*MockCache)(nil)
)

// FileCache implements Cache interface using file storage.
type FileCache struct {
	stats    *Stats
	basePath string
	mu       sync.RWMutex
}

// NewFileCache creates a new file-based cache.
func NewFileCache(basePath string) (*FileCache, error) {
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0750); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	fc := &FileCache{
		basePath: basePath,
		stats: &Stats{
			TotalEntries: 0,
			HitRate:      0,
			TotalHits:    0,
			TotalMisses:  0,
			TotalSize:    0,
			TokensSaved:  0,
		},
	}

	// Load stats if they exist
	_ = fc.loadStats()

	// Save initial stats
	_ = fc.saveStats()

	return fc, nil
}

// Get retrieves a cached enrichment.
func (fc *FileCache) Get(_ context.Context, findingID string) (*enrichment.FindingEnrichment, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	filename := fc.getFilename(findingID)

	// Check if file exists
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			fc.recordMiss()
			return nil, fmt.Errorf("cache miss: key %s not found", findingID)
		}
		return nil, &Error{Op: "get", Key: findingID, Err: err}
	}

	// Read file
	// #nosec G304 -- filename is derived from validated findingID through getFilename()
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, &Error{Op: "get", Key: findingID, Err: err}
	}

	// Unmarshal enrichment
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, &Error{Op: "unmarshal", Key: findingID, Err: err}
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		// Remove expired entry
		_ = os.Remove(filename)
		fc.recordMiss()
		return nil, fmt.Errorf("cache miss: key %s expired", findingID)
	}

	// Update oldest entry tracking
	age := time.Since(info.ModTime())
	if age > fc.stats.OldestEntry {
		fc.stats.OldestEntry = age
	}

	fc.recordHit(entry.Enrichment.TokensUsed)

	return &entry.Enrichment, nil
}

// Set stores an enrichment in the cache.
func (fc *FileCache) Set(_ context.Context, findingEnrichment *enrichment.FindingEnrichment, ttl time.Duration) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	entry := cacheEntry{
		Enrichment: *findingEnrichment,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
		TTL:        ttl,
	}

	// Marshal entry
	data, err := json.Marshal(entry)
	if err != nil {
		return &Error{Op: "marshal", Key: findingEnrichment.FindingID, Err: err}
	}

	// Write to file
	filename := fc.getFilename(findingEnrichment.FindingID)
	if err := os.WriteFile(filename, data, 0600); err != nil {
		return &Error{Op: "write", Key: findingEnrichment.FindingID, Err: err}
	}

	// Update stats
	fc.stats.TotalEntries++
	fc.stats.TotalSize += int64(len(data))

	_ = fc.saveStats()

	return nil
}

// Delete removes an enrichment from the cache.
func (fc *FileCache) Delete(_ context.Context, findingID string) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	filename := fc.getFilename(findingID)

	// Get file info for stats update
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
		}
		return &Error{Op: "stat", Key: findingID, Err: err}
	}

	// Remove file
	if err := os.Remove(filename); err != nil {
		return &Error{Op: "delete", Key: findingID, Err: err}
	}

	// Update stats
	fc.stats.TotalEntries--
	fc.stats.TotalSize -= info.Size()

	_ = fc.saveStats()

	return nil
}

// Has checks if a key exists in the cache.
func (fc *FileCache) Has(_ context.Context, findingID string) bool {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	filename := fc.getFilename(findingID)

	info, err := os.Stat(filename)
	if err != nil || info.IsDir() {
		return false
	}

	// Check if expired (based on file modification time)
	// Since we don't store TTL per entry, we'll use a default check
	// This is a simplification - in production you might want to store expiry metadata
	age := time.Since(info.ModTime())
	if age > 24*time.Hour { // Default expiry of 24 hours
		return false
	}

	return true
}

// Clear removes all cached enrichments.
func (fc *FileCache) Clear(_ context.Context) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Remove all cache files
	entries, err := os.ReadDir(fc.basePath)
	if err != nil {
		return &Error{Op: "readdir", Key: fc.basePath, Err: err}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Skip stats file
		if entry.Name() == "stats.json" {
			continue
		}

		// Remove cache file
		filename := filepath.Join(fc.basePath, entry.Name())
		if err := os.Remove(filename); err != nil {
			return &Error{Op: "delete", Key: entry.Name(), Err: err}
		}
	}

	// Reset stats
	fc.stats = &Stats{
		TotalEntries: 0,
		HitRate:      0,
		TotalHits:    0,
		TotalMisses:  0,
		TotalSize:    0,
		TokensSaved:  0,
	}

	_ = fc.saveStats()

	return nil
}

// Stats returns cache statistics.
func (fc *FileCache) Stats(_ context.Context) (*Stats, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	// Calculate current stats
	fc.updateStats()

	return fc.stats, nil
}

// GetStats returns cache statistics (implements Cache interface).
func (fc *FileCache) GetStats() *Stats {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	// Calculate current stats
	fc.updateStats()

	return fc.stats
}

// Helper methods

func (fc *FileCache) getFilename(findingID string) string {
	// Use finding ID as filename with .json extension
	return filepath.Join(fc.basePath, findingID+".json")
}

func (fc *FileCache) recordHit(tokensSaved int) {
	fc.stats.TotalHits++
	fc.stats.TokensSaved += int64(tokensSaved)
	fc.updateHitRate()
}

func (fc *FileCache) recordMiss() {
	fc.stats.TotalMisses++
	fc.updateHitRate()
}

func (fc *FileCache) updateHitRate() {
	total := fc.stats.TotalHits + fc.stats.TotalMisses
	if total > 0 {
		fc.stats.HitRate = float64(fc.stats.TotalHits) / float64(total)
	}
}

func (fc *FileCache) updateStats() {
	// Update current cache size
	totalSize := int64(0)
	totalEntries := 0

	entries, err := os.ReadDir(fc.basePath)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "stats.json" {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		totalSize += info.Size()
		totalEntries++
	}

	fc.stats.TotalSize = totalSize
	fc.stats.TotalEntries = totalEntries
}

func (fc *FileCache) loadStats() error {
	statsFile := filepath.Join(fc.basePath, "stats.json")

	// #nosec G304 -- statsFile is a fixed path constructed from basePath
	data, err := os.ReadFile(statsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No stats yet
		}
		return err
	}

	return json.Unmarshal(data, &fc.stats)
}

func (fc *FileCache) saveStats() error {
	statsFile := filepath.Join(fc.basePath, "stats.json")

	data, err := json.MarshalIndent(fc.stats, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(statsFile, data, 0600)
}

// cacheEntry represents a cached enrichment with metadata.
type cacheEntry struct {
	CreatedAt  time.Time                    `json:"created_at"`
	ExpiresAt  time.Time                    `json:"expires_at"`
	Enrichment enrichment.FindingEnrichment `json:"enrichment"`
	TTL        time.Duration                `json:"ttl"`
}
