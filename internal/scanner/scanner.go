// Package scanner provides a clean, streaming architecture for security scanners.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/joshsymonds/prismatic/internal/models"
)

// Common errors returned by scanners.
var (
	ErrNoTargets      = errors.New("no targets configured")
	ErrScannerExists  = errors.New("scanner already registered")
	ErrUnknownScanner = errors.New("unknown scanner")
	ErrInvalidConfig  = errors.New("invalid scanner configuration")
	ErrScanInProgress = errors.New("scan already in progress")
	ErrNotImplemented = errors.New("capability not implemented")
)

// Scanner is the core interface that all security scanners must implement.
// Implementations must be safe for concurrent use.
type Scanner interface {
	// Name returns the unique identifier for this scanner instance.
	Name() string

	// Scan executes the security scan and streams findings.
	// The channel is closed when scanning completes.
	// Context cancellation must stop the scan gracefully.
	// Implementation MUST NOT close the channel if error is returned.
	Scan(ctx context.Context) (<-chan Finding, error)

	// Close releases any resources held by the scanner.
	// It must be safe to call multiple times.
	io.Closer
}

// Finding represents a security finding from a scanner.
type Finding struct {
	Finding *models.Finding
	Error   error // Non-nil for partial results or scan errors
}

// Config is implemented by scanner-specific configuration types.
type Config interface {
	// Validate checks if the configuration is valid.
	Validate() error
}

// Targets represents what to scan in a type-safe manner.
type Targets struct {
	Images             []Image
	Filesystems        []Filesystem
	Repositories       []Repository
	CloudAccounts      []CloudAccount
	KubernetesClusters []KubernetesCluster
	WebApplications    []WebApplication
}

// HasTargets returns true if any targets are configured.
func (t *Targets) HasTargets() bool {
	return len(t.Images) > 0 ||
		len(t.Filesystems) > 0 ||
		len(t.Repositories) > 0 ||
		len(t.CloudAccounts) > 0 ||
		len(t.KubernetesClusters) > 0 ||
		len(t.WebApplications) > 0
}

// Image represents a container image target.
type Image struct {
	Auth     *RegistryAuth
	Name     string
	Registry string
}

// Filesystem represents a local filesystem target.
type Filesystem struct {
	Path     string   // Absolute path to scan
	Excludes []string // Glob patterns to exclude
}

// Repository represents a git repository target.
type Repository struct {
	Path   string // Local path (already cloned)
	Remote string // Remote URL for reference
	Branch string // Branch name
	Commit string // Optional specific commit
}

// CloudAccount represents cloud provider credentials.
type CloudAccount struct {
	Creds    any
	Provider string
	Account  string
	Regions  []string
}

// KubernetesCluster represents a k8s cluster target.
type KubernetesCluster struct {
	Context    string   // kubectl context name
	Namespaces []string // Empty means all namespaces
}

// WebApplication represents a web app target.
type WebApplication struct {
	Headers map[string]string
	URL     string
}

// RegistryAuth provides container registry authentication.
type RegistryAuth struct {
	Username string
	Password string
	Token    string
	Server   string // Registry server URL
}

// Factory creates scanner instances with proper configuration.
type Factory interface {
	// Name returns the scanner type name (e.g., "trivy", "nuclei").
	Name() string

	// Create builds a new scanner instance with configuration and targets.
	// The name parameter allows multiple instances of the same scanner type.
	Create(name string, config Config, targets Targets) (Scanner, error)

	// DefaultConfig returns the default configuration for this scanner.
	DefaultConfig() Config

	// Capabilities returns what this scanner can do.
	Capabilities() Capabilities
}

// Capabilities describes scanner capabilities.
type Capabilities struct {
	SupportsImages       bool
	SupportsFilesystems  bool
	SupportsRepositories bool
	SupportsCloud        bool
	SupportsKubernetes   bool
	SupportsWeb          bool
	SupportsConcurrency  bool // Can run multiple scans concurrently
	RequiresNetwork      bool // Needs network access
	MaxConcurrency       int  // Max concurrent scans (0 = unlimited)
}

// Registry manages scanner factories in a thread-safe manner.
type Registry struct {
	factories map[string]Factory
	mu        sync.RWMutex
}

// NewRegistry creates a new scanner registry.
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]Factory),
	}
}

// Register adds a scanner factory to the registry.
// Returns ErrScannerExists if already registered.
func (r *Registry) Register(factory Factory) error {
	if factory == nil {
		return fmt.Errorf("factory is nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	name := factory.Name()
	if _, exists := r.factories[name]; exists {
		return fmt.Errorf("%w: %s", ErrScannerExists, name)
	}

	r.factories[name] = factory
	return nil
}

// Unregister removes a scanner factory from the registry.
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.factories, name)
}

// Get returns a scanner factory by name.
func (r *Registry) Get(name string) (Factory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	factory, exists := r.factories[name]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrUnknownScanner, name)
	}
	return factory, nil
}

// List returns all registered scanner names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}

// CreateScanner creates a scanner instance with the given configuration.
func (r *Registry) CreateScanner(factoryName, instanceName string, config Config, targets Targets) (Scanner, error) {
	factory, err := r.Get(factoryName)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = factory.DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}

	return factory.Create(instanceName, config, targets)
}

// Progress provides real-time scan progress updates.
type Progress struct {
	Finding *models.Finding
	Scanner string
	Phase   string
	Target  string
	Message string
	Current int
	Total   int
}

// ProgressFunc is called with progress updates.
type ProgressFunc func(Progress)

// DefaultRegistry is the global scanner registry used by the application.
// Scanner implementations should register themselves in their init() functions.
var DefaultRegistry = NewRegistry()

// WithProgress creates a scanner that reports progress.
func WithProgress(scanner Scanner, progress ProgressFunc) Scanner {
	return &progressScanner{
		Scanner:  scanner,
		progress: progress,
	}
}

// progressScanner wraps a scanner to report progress.
type progressScanner struct {
	Scanner
	progress ProgressFunc
}

// Scan wraps the underlying scanner's Scan method.
func (ps *progressScanner) Scan(ctx context.Context) (<-chan Finding, error) {
	findings, err := ps.Scanner.Scan(ctx)
	if err != nil {
		return nil, err
	}

	// Create output channel
	out := make(chan Finding)

	go func() {
		defer close(out)

		for finding := range findings {
			// Report finding as progress
			if finding.Finding != nil && ps.progress != nil {
				ps.progress(Progress{
					Scanner: ps.Name(),
					Phase:   "scanning",
					Finding: finding.Finding,
					Message: fmt.Sprintf("Found %s: %s", finding.Finding.Type, finding.Finding.Title),
				})
			}

			// Forward finding
			select {
			case out <- finding:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, nil
}
