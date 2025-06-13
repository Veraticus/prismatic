package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// FileBase implements the Base interface using file storage.
type FileBase struct {
	index    *Index
	basePath string
	mu       sync.RWMutex
}

// NewFileBase creates a new file-based knowledge base.
func NewFileBase(basePath string) (*FileBase, error) {
	// Create base directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0750); err != nil {
		return nil, fmt.Errorf("failed to create knowledge base directory: %w", err)
	}

	fb := &FileBase{
		basePath: basePath,
	}

	// Load or create index
	if err := fb.loadIndex(); err != nil {
		return nil, fmt.Errorf("failed to load index: %w", err)
	}

	return fb, nil
}

// Get retrieves knowledge by ID.
func (fb *FileBase) Get(ctx context.Context, id string) (*Entry, error) {
	fb.mu.RLock()
	defer fb.mu.RUnlock()

	// Check if entry exists in index
	if _, exists := fb.index.Entries[id]; !exists {
		return nil, &EntryNotFoundError{ID: id}
	}

	// Load entry from file
	filename := fb.getFilename(id)
	data, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, fmt.Errorf("failed to read entry file: %w", err)
	}

	var entry Entry
	if err := yaml.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal entry: %w", err)
	}

	// Check if entry has expired
	if fb.isExpired(&entry) {
		return nil, &EntryExpiredError{ID: id}
	}

	return &entry, nil
}

// Search searches for relevant knowledge entries.
func (fb *FileBase) Search(ctx context.Context, query string, limit int) ([]*Entry, error) {
	// First, collect matching IDs while holding the lock
	var matchingIDs []string
	{
		fb.mu.RLock()
		query = strings.ToLower(query)

		// Simple search implementation - can be enhanced with better search algorithms
		for id, indexEntry := range fb.index.Entries {
			// Check if query matches ID, type, tags, or summary
			if strings.Contains(strings.ToLower(id), query) ||
				strings.Contains(strings.ToLower(indexEntry.Type), query) ||
				strings.Contains(strings.ToLower(indexEntry.Summary), query) ||
				fb.matchesTags(indexEntry.Tags, query) {

				matchingIDs = append(matchingIDs, id)

				if len(matchingIDs) >= limit {
					break
				}
			}
		}
		fb.mu.RUnlock()
	}

	// Now load the entries without holding the lock
	var matches []*Entry
	for _, id := range matchingIDs {
		entry, err := fb.Get(ctx, id)
		if err != nil {
			continue // Skip entries that can't be loaded
		}
		matches = append(matches, entry)
	}

	return matches, nil
}

// Store stores a new knowledge entry.
func (fb *FileBase) Store(ctx context.Context, entry *Entry) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	// Set timestamps
	now := time.Now()
	entry.CreatedAt = now
	entry.UpdatedAt = now

	// Save entry to file
	filename := fb.getFilenameForType(entry.ID, entry.Type)
	data, err := yaml.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	// Create directory if needed
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write entry file: %w", err)
	}

	// Update index
	fb.index.Entries[entry.ID] = IndexEntry{
		ID:          entry.ID,
		Type:        entry.Type,
		Tags:        entry.Tags,
		Summary:     fb.generateSummary(entry),
		LastUpdated: now,
	}

	// Update type index
	if fb.index.TypeIndex == nil {
		fb.index.TypeIndex = make(map[string][]string)
	}
	fb.index.TypeIndex[entry.Type] = fb.addToStringSlice(fb.index.TypeIndex[entry.Type], entry.ID)

	// Update tag index
	if fb.index.TagIndex == nil {
		fb.index.TagIndex = make(map[string][]string)
	}
	for _, tag := range entry.Tags {
		fb.index.TagIndex[tag] = fb.addToStringSlice(fb.index.TagIndex[tag], entry.ID)
	}

	// Save index
	return fb.saveIndex()
}

// Update updates an existing entry.
func (fb *FileBase) Update(ctx context.Context, id string, entry *Entry) error {
	// First get the existing entry without holding the lock
	existing, err := fb.Get(ctx, id)
	if err != nil {
		return err
	}

	fb.mu.Lock()
	defer fb.mu.Unlock()

	// Double-check entry still exists
	if _, exists := fb.index.Entries[id]; !exists {
		return &EntryNotFoundError{ID: id}
	}

	// Preserve created timestamp
	entry.CreatedAt = existing.CreatedAt

	entry.ID = id
	entry.UpdatedAt = time.Now()

	// Save updated entry
	filename := fb.getFilename(id)
	data, err := yaml.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write entry file: %w", err)
	}

	// Update index
	fb.index.Entries[id] = IndexEntry{
		ID:          id,
		Type:        entry.Type,
		Tags:        entry.Tags,
		Summary:     fb.generateSummary(entry),
		LastUpdated: entry.UpdatedAt,
	}

	return fb.saveIndex()
}

// Delete removes an entry.
func (fb *FileBase) Delete(ctx context.Context, id string) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	// Check if entry exists
	indexEntry, exists := fb.index.Entries[id]
	if !exists {
		return &EntryNotFoundError{ID: id}
	}

	// Delete file
	filename := fb.getFilename(id)
	if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete entry file: %w", err)
	}

	// Remove from index
	delete(fb.index.Entries, id)

	// Remove from type index
	fb.index.TypeIndex[indexEntry.Type] = fb.removeFromStringSlice(fb.index.TypeIndex[indexEntry.Type], id)

	// Remove from tag index
	for _, tag := range indexEntry.Tags {
		fb.index.TagIndex[tag] = fb.removeFromStringSlice(fb.index.TagIndex[tag], id)
	}

	return fb.saveIndex()
}

// Index rebuilds the search index.
func (fb *FileBase) Index(ctx context.Context) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	// Create new index
	newIndex := &Index{
		LastUpdated: time.Now(),
		Entries:     make(map[string]IndexEntry),
		TypeIndex:   make(map[string][]string),
		TagIndex:    make(map[string][]string),
	}

	// Walk through all YAML files
	err := filepath.WalkDir(fb.basePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YAML files
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}

		// Skip index file
		if filepath.Base(path) == "index.json" {
			return nil
		}

		// Load entry
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		var entry Entry
		if err := yaml.Unmarshal(data, &entry); err != nil {
			return fmt.Errorf("failed to unmarshal %s: %w", path, err)
		}

		// Add to index
		indexEntry := IndexEntry{
			ID:          entry.ID,
			Type:        entry.Type,
			Tags:        entry.Tags,
			Summary:     fb.generateSummary(&entry),
			LastUpdated: entry.UpdatedAt,
		}

		newIndex.Entries[entry.ID] = indexEntry
		newIndex.TypeIndex[entry.Type] = append(newIndex.TypeIndex[entry.Type], entry.ID)

		for _, tag := range entry.Tags {
			newIndex.TagIndex[tag] = append(newIndex.TagIndex[tag], entry.ID)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk directory: %w", err)
	}

	// Replace index
	fb.index = newIndex

	// Save index
	return fb.saveIndex()
}

// Helper methods

func (fb *FileBase) getFilename(id string) string {
	return fb.getFilenameForType(id, "")
}

func (fb *FileBase) getFilenameForType(id, entryType string) string {
	// If type is provided, use it
	if entryType != "" {
		return filepath.Join(fb.basePath, entryType, id+".yaml")
	}

	// Otherwise check if entry exists in index
	if indexEntry, exists := fb.index.Entries[id]; exists && indexEntry.Type != "" {
		return filepath.Join(fb.basePath, indexEntry.Type, id+".yaml")
	}

	// Default to root directory
	return filepath.Join(fb.basePath, id+".yaml")
}

func (fb *FileBase) loadIndex() error {
	indexFile := filepath.Join(fb.basePath, "index.json")

	// Check if index exists
	data, err := os.ReadFile(filepath.Clean(indexFile))
	if err != nil {
		if os.IsNotExist(err) {
			// Create new index
			fb.index = &Index{
				LastUpdated: time.Now(),
				Entries:     make(map[string]IndexEntry),
				TypeIndex:   make(map[string][]string),
				TagIndex:    make(map[string][]string),
			}
			return fb.saveIndex()
		}
		return fmt.Errorf("failed to read index: %w", err)
	}

	var index Index
	if err := json.Unmarshal(data, &index); err != nil {
		return fmt.Errorf("failed to unmarshal index: %w", err)
	}

	fb.index = &index
	return nil
}

func (fb *FileBase) saveIndex() error {
	fb.index.LastUpdated = time.Now()

	data, err := json.MarshalIndent(fb.index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}

	indexFile := filepath.Join(fb.basePath, "index.json")
	if err := os.WriteFile(indexFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write index: %w", err)
	}

	return nil
}

func (fb *FileBase) isExpired(entry *Entry) bool {
	if entry.TTL == 0 {
		return false // No expiration
	}

	expirationTime := entry.UpdatedAt.Add(entry.TTL)
	return time.Now().After(expirationTime)
}

func (fb *FileBase) generateSummary(entry *Entry) string {
	// Create a brief summary for search
	summary := entry.Description
	if len(summary) > 200 {
		summary = summary[:197] + "..."
	}
	return summary
}

func (fb *FileBase) matchesTags(tags []string, query string) bool {
	for _, tag := range tags {
		if strings.Contains(strings.ToLower(tag), query) {
			return true
		}
	}
	return false
}

func (fb *FileBase) addToStringSlice(slice []string, value string) []string {
	// Check if value already exists
	for _, v := range slice {
		if v == value {
			return slice
		}
	}
	return append(slice, value)
}

func (fb *FileBase) removeFromStringSlice(slice []string, value string) []string {
	result := make([]string, 0, len(slice))
	for _, v := range slice {
		if v != value {
			result = append(result, v)
		}
	}
	return result
}

// Error types

type EntryNotFoundError struct {
	ID string
}

func (e *EntryNotFoundError) Error() string {
	return fmt.Sprintf("knowledge entry not found: %s", e.ID)
}

type EntryExpiredError struct {
	ID string
}

func (e *EntryExpiredError) Error() string {
	return fmt.Sprintf("knowledge entry expired: %s", e.ID)
}
