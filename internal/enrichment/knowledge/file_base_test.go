package knowledge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewFileBase(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "kb-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kb, err := NewFileBase(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file base: %v", err)
	}

	if kb.basePath != tmpDir {
		t.Errorf("Expected base path %s, got %s", tmpDir, kb.basePath)
	}

	// Check that entries directory was created
	entriesPath := filepath.Join(tmpDir, "entries")
	if _, err := os.Stat(entriesPath); os.IsNotExist(err) {
		t.Error("Expected entries directory to be created")
	}

	// Check that index file exists
	indexPath := filepath.Join(tmpDir, "index.json")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		t.Error("Expected index.json to be created")
	}
}

func TestFileBase_StoreAndGet(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "kb-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kb, err := NewFileBase(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file base: %v", err)
	}

	ctx := context.Background()

	// Create and store an entry
	entry := &Entry{
		ID:          "test-entry-1",
		Type:        "vulnerability",
		Description: "Test vulnerability entry",
		Tags:        []string{"test", "vulnerability"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		GenericRemediation: &Remediation{
			Immediate: "Test immediate action",
			ShortTerm: "Test short term action",
			LongTerm:  "Test long term action",
		},
	}

	err = kb.Store(ctx, entry)
	if err != nil {
		t.Fatalf("Failed to store entry: %v", err)
	}

	// Get the entry back
	retrieved, err := kb.Get(ctx, entry.ID)
	if err != nil {
		t.Fatalf("Failed to get entry: %v", err)
	}

	if retrieved.ID != entry.ID {
		t.Errorf("Expected ID %s, got %s", entry.ID, retrieved.ID)
	}

	if retrieved.Description != entry.Description {
		t.Errorf("Expected description %s, got %s", entry.Description, retrieved.Description)
	}

	if len(retrieved.Tags) != len(entry.Tags) {
		t.Errorf("Expected %d tags, got %d", len(entry.Tags), len(retrieved.Tags))
	}

	// Try to get non-existent entry
	_, err = kb.Get(ctx, "non-existent")
	if err == nil {
		t.Error("Expected error for non-existent entry")
	}
}

func TestFileBase_Update(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "kb-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kb, err := NewFileBase(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file base: %v", err)
	}

	ctx := context.Background()

	// Store initial entry
	entry := &Entry{
		ID:          "update-test",
		Type:        "vulnerability",
		Description: "Original description",
		Tags:        []string{"original"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err = kb.Store(ctx, entry)
	if err != nil {
		t.Fatalf("Failed to store entry: %v", err)
	}

	// Update the entry
	updatedEntry := &Entry{
		ID:          entry.ID,
		Type:        entry.Type,
		Description: "Updated description",
		Tags:        []string{"updated", "modified"},
		CreatedAt:   entry.CreatedAt,
		UpdatedAt:   time.Now(),
	}

	err = kb.Update(ctx, entry.ID, updatedEntry)
	if err != nil {
		t.Fatalf("Failed to update entry: %v", err)
	}

	// Get updated entry
	retrieved, err := kb.Get(ctx, entry.ID)
	if err != nil {
		t.Fatalf("Failed to get updated entry: %v", err)
	}

	if retrieved.Description != "Updated description" {
		t.Errorf("Expected updated description, got %s", retrieved.Description)
	}

	if len(retrieved.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(retrieved.Tags))
	}

	// Try to update non-existent entry
	err = kb.Update(ctx, "non-existent", updatedEntry)
	if err == nil {
		t.Error("Expected error when updating non-existent entry")
	}
}

func TestFileBase_Delete(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "kb-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kb, err := NewFileBase(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file base: %v", err)
	}

	ctx := context.Background()

	// Store an entry
	entry := &Entry{
		ID:          "delete-test",
		Type:        "vulnerability",
		Description: "Entry to be deleted",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err = kb.Store(ctx, entry)
	if err != nil {
		t.Fatalf("Failed to store entry: %v", err)
	}

	// Verify it exists
	_, err = kb.Get(ctx, entry.ID)
	if err != nil {
		t.Fatal("Entry should exist before deletion")
	}

	// Delete the entry
	err = kb.Delete(ctx, entry.ID)
	if err != nil {
		t.Fatalf("Failed to delete entry: %v", err)
	}

	// Verify it's gone
	_, err = kb.Get(ctx, entry.ID)
	if err == nil {
		t.Error("Expected error when getting deleted entry")
	}

	// Try to delete non-existent entry
	err = kb.Delete(ctx, "non-existent")
	if err == nil {
		t.Error("Expected error when deleting non-existent entry")
	}
}

func TestFileBase_Search(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "kb-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kb, err := NewFileBase(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file base: %v", err)
	}

	ctx := context.Background()

	// Store multiple entries
	entries := []*Entry{
		{
			ID:          "sql-injection",
			Type:        "vulnerability",
			Description: "SQL injection vulnerability in login form",
			Tags:        []string{"sql", "injection", "critical"},
		},
		{
			ID:          "xss-vulnerability",
			Type:        "vulnerability",
			Description: "Cross-site scripting vulnerability",
			Tags:        []string{"xss", "javascript", "high"},
		},
		{
			ID:          "exposed-api",
			Type:        "misconfiguration",
			Description: "API endpoint exposed without authentication",
			Tags:        []string{"api", "exposure", "critical"},
		},
	}

	for _, entry := range entries {
		entry.CreatedAt = time.Now()
		entry.UpdatedAt = time.Now()
		if err := kb.Store(ctx, entry); err != nil {
			t.Fatalf("Failed to store entry %s: %v", entry.ID, err)
		}
	}

	// Search for "critical"
	results, err := kb.Search(ctx, "critical", 10)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results for 'critical', got %d", len(results))
	}

	// Search for "sql"
	results, err = kb.Search(ctx, "sql", 10)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 result for 'sql', got %d", len(results))
	}

	if results[0].ID != "sql-injection" {
		t.Errorf("Expected sql-injection result, got %s", results[0].ID)
	}

	// Search with limit
	results, err = kb.Search(ctx, "vulnerability", 1)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 result with limit 1, got %d", len(results))
	}
}

func TestFileBase_Index(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "kb-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kb, err := NewFileBase(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file base: %v", err)
	}

	ctx := context.Background()

	// Store some entries
	entries := []*Entry{
		{
			ID:        "entry-1",
			Type:      "vulnerability",
			Tags:      []string{"high", "network"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:        "entry-2",
			Type:      "vulnerability",
			Tags:      []string{"critical", "network"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:        "entry-3",
			Type:      "misconfiguration",
			Tags:      []string{"high", "storage"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	for _, entry := range entries {
		if err := kb.Store(ctx, entry); err != nil {
			t.Fatalf("Failed to store entry: %v", err)
		}
	}

	// Force reindex
	err = kb.Index(ctx)
	if err != nil {
		t.Fatalf("Failed to reindex: %v", err)
	}

	// Verify index is correct
	if len(kb.index.Entries) != 3 {
		t.Errorf("Expected 3 entries in index, got %d", len(kb.index.Entries))
	}

	// Check type index
	vulnEntries := kb.index.TypeIndex["vulnerability"]
	if len(vulnEntries) != 2 {
		t.Errorf("Expected 2 vulnerability entries, got %d", len(vulnEntries))
	}

	// Check tag index
	networkEntries := kb.index.TagIndex["network"]
	if len(networkEntries) != 2 {
		t.Errorf("Expected 2 network tagged entries, got %d", len(networkEntries))
	}
}

func TestFileBase_ConcurrentAccess(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "kb-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kb, err := NewFileBase(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create file base: %v", err)
	}

	ctx := context.Background()

	// Test concurrent writes
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			entry := &Entry{
				ID:          fmt.Sprintf("concurrent-%d", id),
				Type:        "test",
				Description: fmt.Sprintf("Concurrent entry %d", id),
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}

			if err := kb.Store(ctx, entry); err != nil {
				t.Errorf("Failed to store concurrent entry %d: %v", id, err)
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all entries were stored
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("concurrent-%d", i)
		if _, err := kb.Get(ctx, id); err != nil {
			t.Errorf("Failed to get concurrent entry %s: %v", id, err)
		}
	}
}
