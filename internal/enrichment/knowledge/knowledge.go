package knowledge

import (
	"context"
	"time"
)

// Base is the interface for the knowledge base.
type Base interface {
	// Get retrieves knowledge by ID
	Get(ctx context.Context, id string) (*Entry, error)

	// Search searches for relevant knowledge entries
	Search(ctx context.Context, query string, limit int) ([]*Entry, error)

	// Store stores a new knowledge entry
	Store(ctx context.Context, entry *Entry) error

	// Update updates an existing entry
	Update(ctx context.Context, id string, entry *Entry) error

	// Delete removes an entry
	Delete(ctx context.Context, id string) error

	// Index rebuilds the search index
	Index(ctx context.Context) error
}

// Entry represents a knowledge base entry.
type Entry struct {
	CreatedAt          time.Time      `yaml:"created_at" json:"created_at"`
	UpdatedAt          time.Time      `yaml:"updated_at" json:"updated_at"`
	Metadata           map[string]any `yaml:"metadata" json:"metadata"`
	GenericRemediation *Remediation   `yaml:"generic_remediation" json:"generic_remediation"`
	ID                 string         `yaml:"id" json:"id"`
	Type               string         `yaml:"type" json:"type"`
	Description        string         `yaml:"description" json:"description"`
	References         []string       `yaml:"references" json:"references"`
	Tags               []string       `yaml:"tags" json:"tags"`
	TTL                time.Duration  `yaml:"ttl" json:"ttl"`
}

// Remediation contains remediation guidance.
type Remediation struct {
	// Immediate contains immediate steps
	Immediate string `yaml:"immediate" json:"immediate"`

	// ShortTerm contains short-term steps
	ShortTerm string `yaml:"short_term" json:"short_term"`

	// LongTerm contains long-term steps
	LongTerm string `yaml:"long_term" json:"long_term"`

	// PreventionSteps to avoid recurrence
	PreventionSteps []string `yaml:"prevention_steps" json:"prevention_steps"`
}

// Index represents the knowledge base index.
type Index struct {
	// LastUpdated is when the index was last updated
	LastUpdated time.Time `json:"last_updated"`

	// Entries maps entry IDs to their metadata
	Entries map[string]IndexEntry `json:"entries"`

	// TypeIndex maps types to entry IDs
	TypeIndex map[string][]string `json:"type_index"`

	// TagIndex maps tags to entry IDs
	TagIndex map[string][]string `json:"tag_index"`
}

// IndexEntry contains indexed metadata for fast lookup.
type IndexEntry struct {
	LastUpdated time.Time `json:"last_updated"`
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Summary     string    `json:"summary"`
	Tags        []string  `json:"tags"`
}

// CVEMetadata contains CVE-specific metadata.
type CVEMetadata struct {
	PublishedDate    time.Time `json:"published_date"`
	CVSSVector       string    `json:"cvss_vector"`
	AffectedProducts []string  `json:"affected_products"`
	CVSSScore        float64   `json:"cvss_score"`
	ExploitAvailable bool      `json:"exploit_available"`
	PatchAvailable   bool      `json:"patch_available"`
}
