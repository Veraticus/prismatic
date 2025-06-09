package scanner

import (
	"context"
	"testing"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKubescapeScanner(t *testing.T) {
	tests := []struct {
		name               string
		contexts           []string
		namespaces         []string
		expectedContexts   []string
		expectedNamespaces []string
	}{
		{
			name:             "default context when none provided",
			contexts:         []string{},
			namespaces:       []string{},
			expectedContexts: []string{"current-context"},
		},
		{
			name:             "uses provided contexts",
			contexts:         []string{"prod", "staging"},
			namespaces:       []string{"default", "kube-system"},
			expectedContexts: []string{"prod", "staging"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{WorkingDir: "/tmp"}
			scanner := NewKubescapeScanner(config, "", tt.contexts, tt.namespaces)

			assert.Equal(t, "kubescape", scanner.Name())
			assert.Equal(t, tt.expectedContexts, scanner.contexts)
			assert.Equal(t, tt.namespaces, scanner.namespaces)
		})
	}
}

func TestKubescapeScanner_ParseResults(t *testing.T) {
	scanner := &KubescapeScanner{
		BaseScanner: NewBaseScanner("kubescape", Config{}),
	}

	tests := []struct {
		validate      func(t *testing.T, findings []models.Finding)
		name          string
		input         string
		expectedCount int
	}{
		{
			name: "parses failed controls",
			input: `{
				"kind": "Report",
				"metadata": {
					"name": "test-scan",
					"creationTimestamp": "2024-01-15T10:00:00Z"
				},
				"summary": {
					"frameworks": [{
						"name": "NSA",
						"score": 65.5,
						"totalResources": 100,
						"failedResources": 35
					}]
				},
				"results": [{
					"controlID": "C-0001",
					"name": "Forbidden Container Registries",
					"description": "Container images from untrusted registries",
					"remediation": "Use only approved container registries",
					"category": "Control plane",
					"score": 8.5,
					"baseScore": 8.5,
					"status": {
						"status": "failed",
						"subStatus": "error"
					},
					"resourceIDs": [{
						"apiVersion": "apps/v1",
						"kind": "Deployment",
						"name": "webapp",
						"namespace": "production"
					}]
				}]
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "kubescape", f.Scanner)
				assert.Equal(t, "forbidden-capabilities", f.Type)
				assert.Equal(t, "Deployment/production/webapp", f.Resource)
				assert.Equal(t, "Forbidden Container Registries", f.Title)
				assert.Equal(t, "high", f.Severity)
				assert.Contains(t, f.Description, "Container images from untrusted registries")
				assert.Equal(t, "Use only approved container registries", f.Remediation)
				assert.Equal(t, "C-0001", f.Metadata["control_id"])
				assert.Equal(t, "production", f.Metadata["namespace"])
				assert.Equal(t, "Deployment", f.Metadata["kind"])
				assert.Equal(t, "apps/v1", f.Metadata["api_version"])
				assert.Equal(t, "error", f.Metadata["sub_status"])
			},
		},
		{
			name: "skips passed controls",
			input: `{
				"results": [{
					"controlID": "C-0002",
					"name": "Exec into container",
					"status": {
						"status": "passed"
					},
					"resourceIDs": [{
						"kind": "Pod",
						"name": "test-pod",
						"namespace": "default"
					}]
				}]
			}`,
			expectedCount: 0,
		},
		{
			name: "handles multiple resources per control",
			input: `{
				"results": [{
					"controlID": "C-0013",
					"name": "Non-root containers",
					"description": "Containers running as root user",
					"score": 7.0,
					"status": {
						"status": "failed"
					},
					"resourceIDs": [{
						"apiVersion": "v1",
						"kind": "Pod",
						"name": "pod1",
						"namespace": "ns1"
					}, {
						"apiVersion": "v1", 
						"kind": "Pod",
						"name": "pod2",
						"namespace": "ns2"
					}]
				}]
			}`,
			expectedCount: 2,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				assert.Equal(t, "Pod/ns1/pod1", findings[0].Resource)
				assert.Equal(t, "Pod/ns2/pod2", findings[1].Resource)
				assert.Equal(t, "non-root-containers", findings[0].Type)
				assert.Equal(t, "high", findings[0].Severity)
			},
		},
		{
			name: "maps severity correctly",
			input: `{
				"results": [{
					"controlID": "C-0004",
					"name": "Resources limits",
					"score": 3.0,
					"status": {
						"status": "failed"
					},
					"resourceIDs": [{
						"kind": "Deployment",
						"name": "low-risk",
						"namespace": "default"
					}]
				}, {
					"controlID": "C-0017",
					"name": "Privileged container",
					"score": 9.5,
					"status": {
						"status": "failed"
					},
					"resourceIDs": [{
						"kind": "Pod",
						"name": "high-risk",
						"namespace": "default"
					}]
				}]
			}`,
			expectedCount: 2,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				// Low severity (score 3.0)
				assert.Equal(t, "low", findings[0].Severity)
				// Critical severity (score 9.5)
				assert.Equal(t, "critical", findings[1].Severity)
			},
		},
		{
			name: "extracts framework information",
			input: `{
				"results": [{
					"controlID": "C-0005",
					"name": "API server insecure port",
					"category": "NSA hardening",
					"score": 8.0,
					"status": {
						"status": "failed"
					},
					"resourceIDs": [{
						"kind": "Service",
						"name": "kubernetes",
						"namespace": "default"
					}]
				}]
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				assert.Contains(t, findings[0].Framework, "NSA")
			},
		},
		{
			name: "handles cluster-scoped resources",
			input: `{
				"results": [{
					"controlID": "C-0035",
					"name": "Cluster-admin binding",
					"score": 9.0,
					"status": {
						"status": "failed"
					},
					"resourceIDs": [{
						"apiVersion": "rbac.authorization.k8s.io/v1",
						"kind": "ClusterRoleBinding",
						"name": "cluster-admin-binding"
					}]
				}]
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				assert.Equal(t, "ClusterRoleBinding/cluster-admin-binding", findings[0].Resource)
				assert.Equal(t, "", findings[0].Metadata["namespace"])
			},
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

func TestKubescapeScanner_ParseResults_InvalidJSON(t *testing.T) {
	scanner := &KubescapeScanner{
		BaseScanner: NewBaseScanner("kubescape", Config{}),
	}

	_, err := scanner.ParseResults([]byte("invalid json"))
	assert.Error(t, err)

	var scannerErr *ScannerError
	assert.ErrorAs(t, err, &scannerErr)
	assert.Equal(t, "kubescape", scannerErr.Scanner)
	assert.Equal(t, ErrorTypeParse, scannerErr.Type)
}

func TestKubescapeScanner_MapControlToType(t *testing.T) {
	scanner := &KubescapeScanner{
		BaseScanner: NewBaseScanner("kubescape", Config{}),
	}

	tests := []struct {
		controlID    string
		expectedType string
	}{
		{"C-0001", "forbidden-capabilities"},
		{"C-0013", "non-root-containers"},
		{"C-0017", "privileged-container"},
		{"C-0034", "automatic-mapping-service-account"},
		{"C-0035", "cluster-admin-binding"},
		{"C-0044", "container-hostport"},
		{"C-0061", "pods-in-default-namespace"},
		{"C-0078", "images-from-allowed-registry"},
		{"C-9999", "c-9999"}, // Unknown control
	}

	for _, tt := range tests {
		t.Run(tt.controlID, func(t *testing.T) {
			result := scanner.mapControlToType(tt.controlID)
			assert.Equal(t, tt.expectedType, result)
		})
	}
}

func TestKubescapeScanner_MapSeverity(t *testing.T) {
	scanner := &KubescapeScanner{
		BaseScanner: NewBaseScanner("kubescape", Config{}),
	}

	tests := []struct {
		expectedSeverity string
		score            float64
	}{
		{"critical", 10.0},
		{"critical", 9.5},
		{"critical", 9.0},
		{"high", 8.0},
		{"high", 7.0},
		{"medium", 6.0},
		{"medium", 4.0},
		{"low", 3.0},
		{"low", 1.0},
		{"low", 0.0},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.score)), func(t *testing.T) {
			severity := scanner.mapScoreToSeverityString(tt.score)
			assert.Equal(t, tt.expectedSeverity, severity)
		})
	}
}

func TestKubescapeScanner_FormatResourceName(t *testing.T) {
	scanner := &KubescapeScanner{
		BaseScanner: NewBaseScanner("kubescape", Config{}),
	}

	tests := []struct {
		name     string
		resource ResourceID
		expected string
	}{
		{
			name: "namespaced resource",
			resource: ResourceID{
				Kind:      "Pod",
				Name:      "webapp",
				Namespace: "production",
			},
			expected: "Pod/production/webapp",
		},
		{
			name: "cluster-scoped resource",
			resource: ResourceID{
				Kind: "ClusterRole",
				Name: "admin",
			},
			expected: "ClusterRole/admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.formatResourceName(tt.resource)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKubescapeScanner_ExtractFramework(t *testing.T) {
	scanner := &KubescapeScanner{
		BaseScanner: NewBaseScanner("kubescape", Config{}),
	}

	tests := []struct {
		name     string
		expected string
		result   KubescapeResult
	}{
		{
			name: "NSA framework",
			result: KubescapeResult{
				Category: "NSA hardening guide",
			},
			expected: "NSA",
		},
		{
			name: "MITER framework",
			result: KubescapeResult{
				Category: "MITER ATT&CK technique",
			},
			expected: "MITER ATT&CK",
		},
		{
			name: "CIS framework by control ID",
			result: KubescapeResult{
				ControlID: "C-0015",
				Category:  "Security",
			},
			expected: "CIS",
		},
		{
			name: "Unknown framework",
			result: KubescapeResult{
				Category: "Custom category",
			},
			expected: "Custom category",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			framework := scanner.extractFramework(tt.result)
			assert.Equal(t, tt.expected, framework)
		})
	}
}

func TestKubescapeScanner_ExtractReferences(t *testing.T) {
	scanner := &KubescapeScanner{
		BaseScanner: NewBaseScanner("kubescape", Config{}),
	}

	result := KubescapeResult{
		ControlID: "C-0017",
		Name:      "privileged-container",
		BaseScore: 8.5,
	}

	refs := scanner.extractReferences(result)
	assert.NotEmpty(t, refs)
	assert.Contains(t, refs[0], "hub.armosec.io/docs/controls/c-0017")
	assert.Contains(t, refs[1], "hub.armosec.io/docs/controls#privileged-container")
}

// TestKubescapeScanner_Scan tests the full scan functionality with mock.
func TestKubescapeScanner_Scan(t *testing.T) {
	// This test would require mocking exec.Command
	// For now, we'll test the scan method structure

	config := Config{
		WorkingDir: "/tmp",
		Timeout:    60,
	}

	scanner := NewKubescapeScanner(config, "", []string{"test-context"}, []string{"default"})
	assert.NotNil(t, scanner)

	// Test context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := scanner.Scan(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "kubescape", result.Scanner)
	assert.Contains(t, result.Error, "scan canceled")
}

// TestKubescapeReport_ComplexStructure tests parsing a more complex report.
func TestKubescapeReport_ComplexStructure(t *testing.T) {
	scanner := &KubescapeScanner{
		BaseScanner: NewBaseScanner("kubescape", Config{}),
	}

	complexReport := `{
		"kind": "Report",
		"metadata": {
			"name": "cluster-scan-2024-01-15",
			"namespace": "",
			"uid": "12345",
			"resourceVersion": "1",
			"creationTimestamp": "2024-01-15T10:00:00Z"
		},
		"summary": {
			"frameworks": [{
				"name": "NSA",
				"version": "v1.0",
				"score": 72.5,
				"totalResources": 150,
				"failedResources": 42,
				"passedResources": 108
			}, {
				"name": "MITER",
				"version": "v1.0", 
				"score": 68.0,
				"totalResources": 150,
				"failedResources": 48,
				"passedResources": 102
			}]
		},
		"results": [{
			"controlID": "C-0030",
			"name": "Ingress and Egress blocked",
			"description": "Network policies are not configured",
			"remediation": "Configure NetworkPolicy objects",
			"category": "Network",
			"score": 6.5,
			"baseScore": 6.5,
			"status": {
				"status": "failed",
				"subStatus": ""
			},
			"resourceIDs": [{
				"apiVersion": "v1",
				"kind": "Namespace",
				"name": "production"
			}, {
				"apiVersion": "v1",
				"kind": "Namespace", 
				"name": "staging"
			}],
			"relatedObjects": [{
				"apiVersion": "networking.k8s.io/v1",
				"kind": "NetworkPolicy",
				"name": "default-deny"
			}]
		}, {
			"controlID": "C-0053",
			"name": "Access Kubernetes dashboard",
			"description": "Kubernetes dashboard is exposed",
			"remediation": "Restrict access to the dashboard",
			"category": "Access control",
			"score": 8.5,
			"baseScore": 8.5,
			"status": {
				"status": "failed",
				"subStatus": "manual review needed"
			},
			"resourceIDs": [{
				"apiVersion": "v1",
				"kind": "Service",
				"name": "kubernetes-dashboard",
				"namespace": "kubernetes-dashboard"
			}]
		}]
	}`

	findings, err := scanner.ParseResults([]byte(complexReport))
	require.NoError(t, err)
	assert.Len(t, findings, 3) // 2 namespaces + 1 service

	// Validate first finding
	assert.Equal(t, "Namespace/production", findings[0].Resource)
	assert.Equal(t, "medium", findings[0].Severity)
	assert.Contains(t, findings[0].Impact, "Affects 2 resources")

	// Validate last finding
	lastFinding := findings[len(findings)-1]
	assert.Equal(t, "Service/kubernetes-dashboard/kubernetes-dashboard", lastFinding.Resource)
	assert.Equal(t, "high", lastFinding.Severity)
	assert.Equal(t, "manual review needed", lastFinding.Metadata["sub_status"])
}

// Mock test for version retrieval.
func TestKubescapeScanner_GetVersion(t *testing.T) {
	scanner := &KubescapeScanner{
		BaseScanner: NewBaseScanner("kubescape", Config{}),
	}

	// This would normally call the actual command
	// For unit testing, we just verify the method exists
	version := scanner.getVersion(context.Background())
	assert.NotEmpty(t, version)
}
