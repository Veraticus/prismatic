package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNucleiScanner(t *testing.T) {
	cfg := Config{}
	endpoints := []string{"https://example.com", "https://test.com"}

	scanner := NewNucleiScanner(cfg, endpoints)
	assert.NotNil(t, scanner)
	assert.Equal(t, "nuclei", scanner.Name())
	assert.Equal(t, endpoints, scanner.endpoints)
}

func TestNucleiScanner_ParseResults(t *testing.T) {
	scanner := &NucleiScanner{
		BaseScanner: NewBaseScanner("nuclei", Config{}),
	}

	tests := []struct {
		validate      func(t *testing.T, findings []models.Finding)
		name          string
		input         string
		expectedCount int
	}{
		{
			name:          "CVE finding",
			input:         `{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","description":"Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.","reference":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228","tags":"cve,cve2021,rce,log4j"},"type":"http","host":"https://example.com","matched-at":"https://example.com/","ip":"93.184.216.34","timestamp":"2024-01-15T10:30:00Z"}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				f := findings[0]
				assert.Equal(t, "nuclei", f.Scanner)
				assert.Equal(t, "CVE", f.Type)
				assert.Equal(t, "Apache Log4j RCE", f.Title)
				assert.Equal(t, models.SeverityCritical, f.Severity)
				assert.Equal(t, "https://example.com", f.Resource)
				assert.Contains(t, f.Description, "Apache Log4j2")
				assert.Contains(t, f.Description, "Detected at: https://example.com/")
				assert.Equal(t, "CVE-2021-44228", f.Metadata["template_id"])
				assert.Equal(t, "93.184.216.34", f.Metadata["ip"])
				assert.Equal(t, "cve,cve2021,rce,log4j", f.Metadata["tags"])
			},
		},
		{
			name:          "SQL injection finding",
			input:         `{"template-id":"sqli-error-based","info":{"name":"SQL Injection - Error Based","severity":"high","tags":"sqli,database,injection"},"type":"http","host":"https://vulnerable.app","matched-at":"https://vulnerable.app/search?q=1'","extracted-results":["You have an error in your SQL syntax"],"ip":"10.0.0.1","timestamp":"2024-01-15T11:00:00Z"}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				f := findings[0]
				assert.Equal(t, "SQL Injection", f.Type)
				assert.Equal(t, "SQL Injection - Error Based", f.Title)
				assert.Equal(t, models.SeverityHigh, f.Severity)
				assert.Contains(t, f.Metadata["extracted"], "You have an error in your SQL syntax")
			},
		},
		{
			name:          "XSS finding",
			input:         `{"template-id":"reflected-xss","info":{"name":"Reflected XSS","severity":"medium","tags":"xss,cross-site-scripting"},"type":"http","host":"https://app.com","matched-at":"https://app.com/comment","ip":"192.168.1.1","timestamp":"2024-01-15T12:00:00Z"}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				f := findings[0]
				assert.Equal(t, "Cross-Site Scripting", f.Type)
				assert.Equal(t, models.SeverityMedium, f.Severity)
			},
		},
		{
			name:          "Technology detection",
			input:         `{"template-id":"apache-detect","info":{"name":"Apache Detection","severity":"info"},"type":"http","host":"https://example.com","matched-at":"https://example.com/","ip":"93.184.216.34","timestamp":"2024-01-15T10:30:00Z"}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				f := findings[0]
				assert.Equal(t, "Technology Detection", f.Type)
				assert.Equal(t, models.SeverityInfo, f.Severity)
			},
		},
		{
			name:          "Admin panel exposure",
			input:         `{"template-id":"wordpress-admin-panel","info":{"name":"WordPress Admin Panel","severity":"low","tags":"panel,wordpress"},"type":"http","host":"https://blog.com","matched-at":"https://blog.com/wp-admin","ip":"10.0.0.2","timestamp":"2024-01-15T13:00:00Z"}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				f := findings[0]
				assert.Equal(t, "Admin Panel Exposure", f.Type)
				assert.Equal(t, models.SeverityLow, f.Severity)
			},
		},
		{
			name: "Multiple findings",
			input: `{"template-id":"CVE-2022-1234","info":{"name":"Test CVE","severity":"high"},"type":"http","host":"https://example.com","matched-at":"https://example.com/test","ip":"1.1.1.1","timestamp":"2024-01-15T10:00:00Z"}
{"template-id":"ssrf-detection","info":{"name":"SSRF Detection","severity":"medium","tags":"ssrf"},"type":"http","host":"https://example.com","matched-at":"https://example.com/api","ip":"1.1.1.1","timestamp":"2024-01-15T10:01:00Z"}
{"template-id":"config-disclosure","info":{"name":"Config File Disclosure","severity":"low"},"type":"http","host":"https://example.com","matched-at":"https://example.com/.env","ip":"1.1.1.1","timestamp":"2024-01-15T10:02:00Z"}`,
			expectedCount: 3,
			validate: func(t *testing.T, findings []models.Finding) {
				assert.Equal(t, "CVE", findings[0].Type)
				assert.Equal(t, "SSRF", findings[1].Type)
				assert.Equal(t, "Information Disclosure", findings[2].Type)
			},
		},
		{
			name:          "Empty input",
			input:         "",
			expectedCount: 0,
		},
		{
			name:          "Invalid JSON",
			input:         "not valid json\n{incomplete",
			expectedCount: 0,
		},
		{
			name: "Mixed valid and invalid",
			input: `{"template-id":"test","info":{"name":"Test","severity":"low"},"type":"http","host":"https://example.com","matched-at":"https://example.com/","ip":"1.1.1.1","timestamp":"2024-01-15T10:00:00Z"}
invalid line
{"template-id":"test2","info":{"name":"Test2","severity":"medium"},"type":"http","host":"https://example.com","matched-at":"https://example.com/test","ip":"1.1.1.1","timestamp":"2024-01-15T10:01:00Z"}`,
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := scanner.ParseResults([]byte(tt.input))
			require.NoError(t, err)
			assert.Len(t, findings, tt.expectedCount)

			if tt.validate != nil && len(findings) > 0 {
				tt.validate(t, findings)
			}
		})
	}
}

func TestNucleiScanner_mapTemplateToType(t *testing.T) {
	scanner := &NucleiScanner{
		BaseScanner: NewBaseScanner("nuclei", Config{}),
	}

	tests := []struct {
		templateID   string
		tags         string
		expectedType string
	}{
		// CVE patterns
		{"CVE-2021-44228", "", "CVE"},
		{"cve-2022-1234", "", "CVE"},

		// Tag-based categorization
		{"generic-sqli", "sqli,database", "SQL Injection"},
		{"error-based-sqli", "sql-injection", "SQL Injection"},
		{"reflected-xss", "xss,web", "Cross-Site Scripting"},
		{"stored-xss", "cross-site-scripting", "Cross-Site Scripting"},
		{"lfi-linux", "lfi,linux", "Local File Inclusion"},
		{"rce-php", "rce,php", "Remote Code Execution"},
		{"ssrf-detection", "ssrf,web", "SSRF"},
		{"xxe-injection", "xxe,xml", "XXE"},
		{"apache-misconfiguration", "misconfig,apache", "Misconfiguration"},
		{"sensitive-data-exposure", "exposure,sensitive", "Information Exposure"},
		{"weak-authentication", "auth,weak", "Authentication Issue"},

		// Template ID patterns
		{"apache-detect", "", "Technology Detection"},
		{"wordpress-admin-panel", "", "Admin Panel Exposure"},
		{"nginx-config", "", "Configuration Issue"},
		{"api-key-disclosure", "", "Information Disclosure"},

		// Default case
		{"some-random-check", "", "Web Vulnerability"},
	}

	for _, tt := range tests {
		t.Run(tt.templateID, func(t *testing.T) {
			result := scanner.mapTemplateToType(tt.templateID, tt.tags)
			assert.Equal(t, tt.expectedType, result)
		})
	}
}

func TestNucleiScanner_buildDescription(t *testing.T) {
	scanner := &NucleiScanner{
		BaseScanner: NewBaseScanner("nuclei", Config{}),
	}

	tests := []struct {
		name     string
		result   nucleiResult
		expected []string
	}{
		{
			name: "Full description",
			result: nucleiResult{
				Info: nucleiInfo{
					Description: "This is a vulnerability",
					Reference:   "https://example.com/ref",
				},
				MatchedAt:        "https://target.com/path",
				ExtractedResults: []string{"extracted1", "extracted2"},
			},
			expected: []string{
				"This is a vulnerability",
				"Detected at: https://target.com/path",
				"Reference: https://example.com/ref",
				"Extracted: extracted1, extracted2",
			},
		},
		{
			name: "Minimal description",
			result: nucleiResult{
				MatchedAt: "https://target.com/",
			},
			expected: []string{
				"Detected at: https://target.com/",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := scanner.buildDescription(tt.result)
			for _, exp := range tt.expected {
				assert.Contains(t, desc, exp)
			}
		})
	}
}

func TestNucleiScanner_Scan(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	cfg := Config{
		Env: map[string]string{
			"HOME": "/tmp",
		},
	}

	t.Run("No endpoints", func(t *testing.T) {
		scanner := NewNucleiScanner(cfg, []string{})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result, err := scanner.Scan(ctx)
		require.NoError(t, err)
		assert.Empty(t, result.Error)
		assert.Empty(t, result.Findings)
	})

	t.Run("With endpoints", func(t *testing.T) {
		// This test requires nuclei to be installed
		scanner := NewNucleiScanner(cfg, []string{"https://example.com"})

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := scanner.Scan(ctx)
		// Don't fail if nuclei is not installed
		if err != nil && strings.Contains(err.Error(), "nuclei not found") {
			t.Skip("Nuclei not installed")
		}

		if err == nil {
			assert.Empty(t, result.Error)
			assert.NotNil(t, result.StartTime)
			assert.NotNil(t, result.EndTime)
		}
	})
}

func TestNucleiScanner_resultToFinding(t *testing.T) {
	scanner := &NucleiScanner{
		BaseScanner: NewBaseScanner("nuclei", Config{}),
	}

	result := nucleiResult{
		TemplateID: "CVE-2021-44228",
		Info: nucleiInfo{
			Name:        "Apache Log4j RCE",
			Severity:    "critical",
			Description: "Log4j vulnerability",
			Reference:   "https://nvd.nist.gov",
			Tags:        "cve,rce",
		},
		Type:             "http",
		Host:             "https://example.com",
		MatchedAt:        "https://example.com/app",
		ExtractedResults: []string{"version 2.14.0"},
		IP:               "1.2.3.4",
		Timestamp:        "2024-01-15T10:00:00Z",
	}

	finding := scanner.resultToFinding(result)

	assert.NotEmpty(t, finding.ID)
	assert.Equal(t, "nuclei", finding.Scanner)
	assert.Equal(t, "CVE", finding.Type)
	assert.Equal(t, "Apache Log4j RCE", finding.Title)
	assert.Equal(t, models.SeverityCritical, finding.Severity)
	assert.Equal(t, "https://example.com", finding.Resource)
	assert.Equal(t, "https://example.com:https://example.com/app", finding.Location)

	// Check metadata
	assert.Equal(t, "CVE-2021-44228", finding.Metadata["template_id"])
	assert.Equal(t, "Apache Log4j RCE", finding.Metadata["template_name"])
	assert.Equal(t, "https://example.com/app", finding.Metadata["matched_at"])
	assert.Equal(t, "http", finding.Metadata["type"])
	assert.Equal(t, "1.2.3.4", finding.Metadata["ip"])
	assert.Equal(t, "2024-01-15T10:00:00Z", finding.Metadata["timestamp"])
	assert.Equal(t, "Log4j vulnerability", finding.Metadata["template_description"])
	assert.Equal(t, "https://nvd.nist.gov", finding.Metadata["reference"])
	assert.Equal(t, "cve,rce", finding.Metadata["tags"])
	assert.Equal(t, "version 2.14.0", finding.Metadata["extracted"])

	// Validate finding
	err := finding.IsValid()
	assert.NoError(t, err)
}
