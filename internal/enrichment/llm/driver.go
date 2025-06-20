package llm

import (
	"context"

	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
)

// Driver is the interface that all LLM drivers must implement.
type Driver interface {
	// Enrich takes a batch of findings and returns enrichments
	Enrich(ctx context.Context, findings []models.Finding, prompt string) ([]enrichment.FindingEnrichment, error)

	// GetCapabilities returns the driver's capabilities
	GetCapabilities() Capabilities

	// EstimateTokens estimates the number of tokens for a given prompt
	EstimateTokens(prompt string) (int, error)

	// HealthCheck verifies the driver is working
	HealthCheck(ctx context.Context) error

	// Configure sets driver-specific configuration
	Configure(config map[string]any) error
}

// Capabilities describes what an LLM driver can do.
type Capabilities struct {
	ModelName               string
	MaxTokensPerRequest     int
	MaxTokensPerResponse    int
	CostPer1KTokens         float64
	SupportsJSONMode        bool
	SupportsFunctionCalling bool
}

// DriverRegistry manages available LLM drivers.
type DriverRegistry struct {
	drivers map[string]func() Driver
}

// NewDriverRegistry creates a new driver registry.
func NewDriverRegistry() *DriverRegistry {
	return &DriverRegistry{
		drivers: make(map[string]func() Driver),
	}
}

// Register registers a new driver.
func (r *DriverRegistry) Register(name string, factory func() Driver) {
	r.drivers[name] = factory
}

// Get returns a driver by name.
func (r *DriverRegistry) Get(name string) (Driver, error) {
	factory, ok := r.drivers[name]
	if !ok {
		return nil, &DriverNotFoundError{Name: name}
	}
	return factory(), nil
}

// DriverNotFoundError is returned when a requested driver doesn't exist.
type DriverNotFoundError struct {
	Name string
}

func (e *DriverNotFoundError) Error() string {
	return "driver not found: " + e.Name
}

// DefaultRegistry is the global driver registry.
var DefaultRegistry = NewDriverRegistry()
