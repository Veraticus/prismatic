package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/joshsymonds/prismatic/internal/enrichment"
)

// MockCache implements Cache for testing.
type MockCache struct {
	GetFunc    func(ctx context.Context, findingID string) (*enrichment.FindingEnrichment, error)
	SetFunc    func(ctx context.Context, findingEnrichment *enrichment.FindingEnrichment, ttl time.Duration) error
	DeleteFunc func(ctx context.Context, findingID string) error
	HasFunc    func(ctx context.Context, findingID string) bool
	ClearFunc  func(ctx context.Context) error
	StatsFunc  func(ctx context.Context) (*Stats, error)
}

// Get implements Cache interface.
func (m *MockCache) Get(ctx context.Context, findingID string) (*enrichment.FindingEnrichment, error) {
	if m.GetFunc != nil {
		return m.GetFunc(ctx, findingID)
	}
	return nil, &Error{Op: "get", Key: findingID, Err: fmt.Errorf("not found")}
}

// Set implements Cache interface.
func (m *MockCache) Set(ctx context.Context, findingEnrichment *enrichment.FindingEnrichment, ttl time.Duration) error {
	if m.SetFunc != nil {
		return m.SetFunc(ctx, findingEnrichment, ttl)
	}
	return nil
}

// Delete implements Cache interface.
func (m *MockCache) Delete(ctx context.Context, findingID string) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, findingID)
	}
	return nil
}

// Has implements Cache interface.
func (m *MockCache) Has(ctx context.Context, findingID string) bool {
	if m.HasFunc != nil {
		return m.HasFunc(ctx, findingID)
	}
	return false
}

// Clear implements Cache interface.
func (m *MockCache) Clear(ctx context.Context) error {
	if m.ClearFunc != nil {
		return m.ClearFunc(ctx)
	}
	return nil
}

// Stats implements Cache interface.
func (m *MockCache) Stats(ctx context.Context) (*Stats, error) {
	if m.StatsFunc != nil {
		return m.StatsFunc(ctx)
	}
	return &Stats{}, nil
}

// GetStats implements Cache interface.
func (m *MockCache) GetStats() *Stats {
	if m.StatsFunc != nil {
		stats, _ := m.StatsFunc(context.Background())
		return stats
	}
	return &Stats{}
}

// NewMockCache creates a new mock cache for testing.
func NewMockCache() *MockCache {
	return &MockCache{}
}
