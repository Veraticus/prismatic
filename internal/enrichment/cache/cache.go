package cache

import (
	"time"
)

// Cache defines the interface for caching enrichments.

// KeyGenerator generates cache keys for findings.

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

// KeyGenerator generates cache keys for findings.

// DefaultKeyGenerator is the default key generator.
type DefaultKeyGenerator struct{}

// GenerateKey implements KeyGenerator.
func (g *DefaultKeyGenerator) GenerateKey(findingID string, context map[string]interface{}) string {
	// Simple implementation - can be enhanced to include context
	return findingID
}

// CacheError represents a cache-specific error.
type CacheError struct {
	Err error
	Op  string
	Key string
}

func (e *CacheError) Error() string {
	return "cache " + e.Op + " failed for key " + e.Key + ": " + e.Err.Error()
}

func (e *CacheError) Unwrap() error {
	return e.Err
}
