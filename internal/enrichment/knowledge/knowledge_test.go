package knowledge

import (
	"testing"
	"time"
)

func TestEntryCreation(t *testing.T) {
	now := time.Now()

	entry := &Entry{
		ID:          "cve-2021-1234",
		Type:        "vulnerability",
		Description: "Test vulnerability",
		References:  []string{"https://cve.mitre.org/cve-2021-1234"},
		Tags:        []string{"security", "critical", "rce"},
		CreatedAt:   now,
		UpdatedAt:   now,
		TTL:         24 * time.Hour,
		Metadata: map[string]interface{}{
			"cvss_score": 9.8,
			"exploited":  true,
		},
		GenericRemediation: &Remediation{
			Immediate: "Apply security patch immediately",
			ShortTerm: "Update to version 2.0.1 or later",
			LongTerm:  "Implement security scanning in CI/CD",
			PreventionSteps: []string{
				"Enable automatic security updates",
				"Implement vulnerability scanning",
			},
		},
	}

	if entry.ID != "cve-2021-1234" {
		t.Errorf("Expected ID 'cve-2021-1234', got %s", entry.ID)
	}

	if len(entry.Tags) != 3 {
		t.Errorf("Expected 3 tags, got %d", len(entry.Tags))
	}

	if entry.GenericRemediation == nil {
		t.Error("Expected generic remediation to be set")
	}

	if len(entry.GenericRemediation.PreventionSteps) != 2 {
		t.Errorf("Expected 2 prevention steps, got %d", len(entry.GenericRemediation.PreventionSteps))
	}
}

func TestRemediationSteps(t *testing.T) {
	remediation := &Remediation{
		Immediate: "Isolate affected systems",
		ShortTerm: "Apply patches and updates",
		LongTerm:  "Implement security monitoring",
		PreventionSteps: []string{
			"Regular security audits",
			"Automated patch management",
			"Security training for developers",
		},
	}

	if remediation.Immediate == "" {
		t.Error("Immediate remediation should not be empty")
	}

	if len(remediation.PreventionSteps) != 3 {
		t.Errorf("Expected 3 prevention steps, got %d", len(remediation.PreventionSteps))
	}
}

func TestIndexOperations(t *testing.T) {
	index := &Index{
		LastUpdated: time.Now(),
		Entries:     make(map[string]IndexEntry),
		TypeIndex:   make(map[string][]string),
		TagIndex:    make(map[string][]string),
	}

	// Add entries to index
	entries := []IndexEntry{
		{
			ID:          "entry-1",
			Type:        "vulnerability",
			Summary:     "Critical RCE vulnerability",
			Tags:        []string{"critical", "rce"},
			LastUpdated: time.Now(),
		},
		{
			ID:          "entry-2",
			Type:        "misconfiguration",
			Summary:     "S3 bucket public access",
			Tags:        []string{"aws", "s3", "exposure"},
			LastUpdated: time.Now(),
		},
	}

	// Build index
	for _, entry := range entries {
		index.Entries[entry.ID] = entry

		// Update type index
		index.TypeIndex[entry.Type] = append(index.TypeIndex[entry.Type], entry.ID)

		// Update tag index
		for _, tag := range entry.Tags {
			index.TagIndex[tag] = append(index.TagIndex[tag], entry.ID)
		}
	}

	// Test index lookups
	if len(index.Entries) != 2 {
		t.Errorf("Expected 2 entries in index, got %d", len(index.Entries))
	}

	// Test type index
	vulnEntries := index.TypeIndex["vulnerability"]
	if len(vulnEntries) != 1 || vulnEntries[0] != "entry-1" {
		t.Error("Type index lookup failed for 'vulnerability'")
	}

	// Test tag index
	criticalEntries := index.TagIndex["critical"]
	if len(criticalEntries) != 1 || criticalEntries[0] != "entry-1" {
		t.Error("Tag index lookup failed for 'critical'")
	}

	awsEntries := index.TagIndex["aws"]
	if len(awsEntries) != 1 || awsEntries[0] != "entry-2" {
		t.Error("Tag index lookup failed for 'aws'")
	}
}

func TestCVEMetadata(t *testing.T) {
	metadata := &CVEMetadata{
		CVSSScore:        9.8,
		CVSSVector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		PublishedDate:    time.Now().Add(-30 * 24 * time.Hour), // 30 days ago
		ExploitAvailable: true,
		PatchAvailable:   true,
		AffectedProducts: []string{
			"product-a v1.0-1.5",
			"product-b v2.0-2.3",
		},
	}

	if metadata.CVSSScore != 9.8 {
		t.Errorf("Expected CVSS score 9.8, got %f", metadata.CVSSScore)
	}

	if !metadata.ExploitAvailable {
		t.Error("Expected exploit to be available")
	}

	if len(metadata.AffectedProducts) != 2 {
		t.Errorf("Expected 2 affected products, got %d", len(metadata.AffectedProducts))
	}
}

func TestEntryTTL(t *testing.T) {
	entry := &Entry{
		ID:        "test-entry",
		CreatedAt: time.Now().Add(-25 * time.Hour), // Created 25 hours ago
		TTL:       24 * time.Hour,
	}

	// Check if entry is expired
	age := time.Since(entry.CreatedAt)
	isExpired := age > entry.TTL

	if !isExpired {
		t.Error("Expected entry to be expired after 24 hours")
	}
}

func TestSearchRelevance(t *testing.T) {
	entries := []*Entry{
		{
			ID:          "1",
			Type:        "vulnerability",
			Description: "SQL injection vulnerability in login form",
			Tags:        []string{"sql", "injection", "auth"},
		},
		{
			ID:          "2",
			Type:        "vulnerability",
			Description: "Cross-site scripting (XSS) vulnerability",
			Tags:        []string{"xss", "javascript"},
		},
		{
			ID:          "3",
			Type:        "misconfiguration",
			Description: "Database exposed to internet without authentication",
			Tags:        []string{"database", "exposure", "auth"},
		},
	}

	// Simulate search for "auth" - should return entries 1 and 3
	var results []*Entry
	query := "auth"

	for _, entry := range entries {
		// Check description
		if contains(entry.Description, query) {
			results = append(results, entry)
			continue
		}

		// Check tags
		for _, tag := range entry.Tags {
			if contains(tag, query) {
				results = append(results, entry)
				break
			}
		}
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results for query 'auth', got %d", len(results))
	}
}

// Helper function for string contains (case-insensitive).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsIgnoreCase(s, substr)
}

func containsIgnoreCase(s, substr string) bool {
	if substr == "" {
		return true
	}
	if len(s) < len(substr) {
		return false
	}

	// Simple case-insensitive contains implementation
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if toLowerCase(s[i+j]) != toLowerCase(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func toLowerCase(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
