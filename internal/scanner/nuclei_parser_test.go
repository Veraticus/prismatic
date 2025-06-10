package scanner

import (
	"testing"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNucleiScanner_ParseRealOutput tests parsing of actual Nuclei output.
// Test data is generated from real Nuclei scans - see scripts/test/generate-nuclei-testdata-with-server.sh.
func TestNucleiScanner_ParseRealOutput(t *testing.T) {
	scanner := NewNucleiScannerWithLogger(Config{}, []string{}, logger.GetGlobalLogger())

	tests := []struct {
		validate      func(t *testing.T, findings []models.Finding)
		name          string
		input         string
		expectedCount int
	}{
		{
			name:          "Real Apache detection - ACTUAL Nuclei output with all fields",
			input:         `{"template":"http/technologies/apache/apache-detect.yaml","template-url":"https://cloud.projectdiscovery.io/public/apache-detect","template-id":"apache-detect","template-path":"/home/joshsymonds/nuclei-templates/http/technologies/apache/apache-detect.yaml","info":{"name":"Apache Detection","author":["philippedelteil"],"tags":["tech","apache"],"description":"Some Apache servers have the version on the response header. The OpenSSL version can be also obtained","severity":"info","metadata":{"max-request":1}},"type":"http","host":"localhost:8888","port":"8888","scheme":"http","url":"http://localhost:8888","matched-at":"http://localhost:8888","extracted-results":["Apache/2.4.41 (Ubuntu)"],"request":"GET / HTTP/1.1\r\nHost: localhost:8888\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/117.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n","response":"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 497\r\nContent-Type: text/html; charset=utf-8\r\nDate: Tue, 10 Jun 2025 03:53:33 GMT\r\nServer: Apache/2.4.41 (Ubuntu)\r\nX-Aspnet-Version: 4.0.30319\r\nX-Powered-By: PHP/7.4.3\r\n\r\n<!DOCTYPE html>\n<html>\n<head>\n    <title>Test Application - Prismatic Scanner Test</title>\n    <meta name=\"generator\" content=\"WordPress 5.8.1\" />\n    <meta name=\"description\" content=\"Test server for Nuclei scanning\" />\n</head>\n<body>\n    <h1>Welcome to Test Server</h1>\n    <!-- Powered by Apache/2.4.41 -->\n    <div id=\"wp-content\">\n        <p>This is a test server for security scanning.</p>\n    </div>\n    <script src=\"/wp-includes/js/jquery/jquery.min.js?ver=3.6.0\"></script>\n</body>\n</html>","ip":"127.0.0.1","timestamp":"2025-06-09T20:53:33.436532101-07:00","curl-command":"curl -X 'GET' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/117.0' 'http://localhost:8888'","matcher-status":true}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "nuclei", f.Scanner)
				assert.Equal(t, "Technology Detection", f.Type)
				assert.Equal(t, "Apache Detection", f.Title)
				assert.Equal(t, models.SeverityInfo, f.Severity)
				assert.Equal(t, "localhost:8888", f.Resource)
				assert.Contains(t, f.Description, "Apache servers")
				assert.Equal(t, "apache-detect", f.Metadata["template_id"])
				assert.Contains(t, f.Metadata["tags"], "tech")

				// Verify extracted results are captured
				assert.Contains(t, f.Description, "Apache/2.4.41")
			},
		},
		{
			name:          "Real Git exposure - ACTUAL Nuclei output",
			input:         `{"template":"http/exposures/configs/git-config.yaml","template-url":"https://cloud.projectdiscovery.io/public/git-config","template-id":"git-config","template-path":"/home/joshsymonds/nuclei-templates/http/exposures/configs/git-config.yaml","info":{"name":"Git Configuration - Detect","author":["Ice3man","DhiyaneshDK"],"tags":["config","git","exposure"],"description":"Git configuration was detected via the pattern /.git/config and log file on passed URLs.","severity":"medium","metadata":{"max-request":1},"classification":{"cve-id":null,"cwe-id":["cwe-538","cwe-200"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","cvss-score":5.3}},"type":"http","host":"localhost:8888","port":"8888","scheme":"http","url":"http://localhost:8888/.git/config","matched-at":"http://localhost:8888/.git/config","request":"GET /.git/config HTTP/1.1\r\nHost: localhost:8888\r\nUser-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n","response":"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 289\r\nContent-Type: text/plain; charset=utf-8\r\nDate: Tue, 10 Jun 2025 03:54:27 GMT\r\n\r\n[core]\n    repositoryformatversion = 0\n    filemode = true\n    bare = false\n    logallrefupdates = true\n[remote \"origin\"]\n    url = https://github.com/example/private-repo.git\n    fetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"master\"]\n    remote = origin\n    merge = refs/heads/master\n[user]\n    email = developer@example.com\n    name = Developer Name","ip":"127.0.0.1","timestamp":"2025-06-09T20:54:27.379871551-07:00","curl-command":"curl -X 'GET' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148' 'http://localhost:8888/.git/config'","matcher-status":true}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "Misconfiguration", f.Type) // Has 'config' tag which matches first
				assert.Equal(t, models.SeverityMedium, f.Severity)
				assert.Contains(t, f.Title, "Git Configuration")
				assert.Equal(t, "localhost:8888", f.Resource)                                   // Host
				assert.Equal(t, "localhost:8888:http://localhost:8888/.git/config", f.Location) // Host:MatchedAt
			},
		},
		{
			name:          "Git exposure",
			input:         `{"template-id":"git-config","info":{"name":"Git Config File","severity":"medium","description":"Git config file exposed","tags":["exposure","git"],"author":["Ice3man"]},"type":"http","host":"http://example.com","matched-at":"http://example.com/.git/config","ip":"93.184.216.34","timestamp":"2024-01-01T12:00:01Z"}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "Information Exposure", f.Type)
				assert.Equal(t, models.SeverityMedium, f.Severity)
				assert.Contains(t, f.Title, "Git Config")
			},
		},
		{
			name:          "Panel detection",
			input:         `{"template-id":"wordpress-admin-panel","info":{"name":"WordPress Admin Panel","severity":"low","tags":["panel","wordpress"],"author":["random-robbie"]},"type":"http","host":"https://blog.com","matched-at":"https://blog.com/wp-admin","ip":"10.0.0.2","timestamp":"2024-01-15T13:00:00Z"}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "Admin Panel Exposure", f.Type)
				assert.Equal(t, models.SeverityLow, f.Severity)
			},
		},
		{
			name: "Multiple findings",
			input: `{"template-id":"CVE-2022-1234","info":{"name":"Test CVE","severity":"high","author":["test"]},"type":"http","host":"https://example.com","matched-at":"https://example.com/test","ip":"1.1.1.1","timestamp":"2024-01-15T10:00:00Z"}
{"template-id":"exposed-phpinfo","info":{"name":"phpinfo Disclosure","severity":"low","tags":["exposure","phpinfo"],"author":["test"]},"type":"http","host":"https://example.com","matched-at":"https://example.com/phpinfo.php","ip":"1.1.1.1","timestamp":"2024-01-15T10:01:00Z"}`,
			expectedCount: 2,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				assert.Equal(t, "CVE", findings[0].Type)
				assert.Equal(t, "Information Exposure", findings[1].Type)
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
		{"reflected-xss", "xss,web", "Cross-Site Scripting"},
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
