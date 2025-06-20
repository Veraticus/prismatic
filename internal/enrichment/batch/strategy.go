package batch

import (
	"context"

	"github.com/joshsymonds/prismatic/internal/models"
)

// BatchingStrategy defines the interface for batching strategies.
type BatchingStrategy interface {
	// Batch groups findings into batches for efficient processing
	Batch(ctx context.Context, findings []models.Finding, config *Config) ([]Batch, error)

	// Name returns the strategy name
	Name() string

	// Description returns a human-readable description
	Description() string
}

// Config contains configuration for batching.
type Config struct {
	ClientContext       map[string]any
	GroupBy             []string
	MaxTokensPerBatch   int
	MaxFindingsPerBatch int
}

// Batch represents a group of findings to be processed together.
type Batch struct {
	ID              string
	Strategy        string
	GroupKey        string
	SummaryReason   string
	Findings        []models.Finding
	EstimatedTokens int
	Priority        int
	ShouldSummarize bool
}

// StrategyRegistry manages available batching strategies.
type StrategyRegistry struct {
	strategies map[string]func() BatchingStrategy
}

// NewStrategyRegistry creates a new strategy registry.
func NewStrategyRegistry() *StrategyRegistry {
	return &StrategyRegistry{
		strategies: make(map[string]func() BatchingStrategy),
	}
}

// Register registers a new strategy.
func (r *StrategyRegistry) Register(name string, factory func() BatchingStrategy) {
	r.strategies[name] = factory
}

// Get returns a strategy by name.
func (r *StrategyRegistry) Get(name string) (BatchingStrategy, error) {
	factory, ok := r.strategies[name]
	if !ok {
		return nil, &StrategyNotFoundError{Name: name}
	}
	return factory(), nil
}

// StrategyNotFoundError is returned when a requested strategy doesn't exist.
type StrategyNotFoundError struct {
	Name string
}

func (e *StrategyNotFoundError) Error() string {
	return "batching strategy not found: " + e.Name
}

// DefaultRegistry is the global strategy registry.
var DefaultRegistry = NewStrategyRegistry()
