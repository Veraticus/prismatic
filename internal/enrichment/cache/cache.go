package cache

import (
	"context"
	"time"

	"github.com/joshsymonds/prismatic/internal/enrichment"
)

// Cache defines the interface for caching enrichments.
type Cache interface {
	// Get retrieves an enrichment from the cache
	Get(ctx context.Context, findingID string) (*enrichment.FindingEnrichment, error)
	
	// Set stores an enrichment in the cache
	Set(ctx context.Context, enrichment *enrichment.FindingEnrichment, ttl time.Duration) error
	
	// Delete removes an enrichment from the cache
	Delete(ctx context.Context, findingID string) error
	
	// Clear removes all entries from the cache
	Clear(ctx context.Context) error
	
	// Stats returns cache statistics
	Stats(ctx context.Context) (*Stats, error)
}

// KeyGenerator generates cache keys for findings.
type KeyGenerator interface {
	// GenerateKey creates a cache key for a finding
	GenerateKey(findingID string, context map[string]interface{}) string
}

// Stats contains cache statistics.
type Stats struct {
	// TotalEntries is the number of cached entries
	TotalEntries int

	// HitRate is the cache hit rate (0-1)
	HitRate float64

	// TotalHits is the number of cache hits
	TotalHits int64

	// TotalMisses is the number of cache misses
	TotalMisses int64

	// TotalSize is the total size in bytes
	TotalSize int64

	// OldestEntry is the age of the oldest entry
	OldestEntry time.Duration

	// TokensSaved is the estimated tokens saved by caching
	TokensSaved int64
}

// DefaultKeyGenerator is the default key generator.
type DefaultKeyGenerator struct{}

// GenerateKey implements KeyGenerator.
func (g *DefaultKeyGenerator) GenerateKey(findingID string, _ map[string]interface{}) string {
	// Simple implementation - can be enhanced to include context
	return findingID
}

// Error represents a cache-specific error.
type Error struct {
	Err error
	Op  string
	Key string
}

func (e *Error) Error() string {
	return "cache " + e.Op + " failed for key " + e.Key + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error {
	return e.Err
}
