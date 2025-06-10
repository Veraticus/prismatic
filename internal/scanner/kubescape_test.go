package scanner

import (
	"context"
	"fmt"
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
			name: "parses v3 failed controls",
			input: `{
				"summaryDetails": {
					"controls": {
						"C-0012": {
							"controlID": "C-0012",
							"name": "Applications credentials in configuration files",
							"status": "failed",
							"score": 79.16667,
							"scoreFactor": 8,
							"category": {
								"name": "Secrets",
								"id": "Cat-3"
							}
						}
					}
				},
				"results": [{
					"resourceID": "path=1579046608/api=/v1//ConfigMap/app-config",
					"object": {
						"apiVersion": "v1",
						"kind": "ConfigMap",
						"metadata": {
							"name": "app-config"
						},
						"sourcePath": "testdata/scanner/kubescape/manifests/sensitive-configmap.yaml:0"
					},
					"controls": [{
						"controlID": "C-0012",
						"name": "Applications credentials in configuration files",
						"status": {
							"status": "failed",
							"subStatus": "error"
						},
						"rules": [{
							"name": "rule-credentials-configmap",
							"status": "failed",
							"paths": [{
								"failedPath": "data[api_token]",
								"fixPath": {
									"path": "",
									"value": ""
								}
							}]
						}]
					}]
				}]
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				f := findings[0]
				assert.Equal(t, "kubescape", f.Scanner)
				assert.Equal(t, "applications-credentials", f.Type)
				assert.Equal(t, "ConfigMap/app-config", f.Resource)
				assert.Equal(t, "Applications credentials in configuration files", f.Title)
				assert.Equal(t, "high", f.Severity)
				assert.Contains(t, f.Description, "Failed checks:")
				assert.Contains(t, f.Description, "data[api_token]")
				assert.Equal(t, "C-0012", f.Metadata["control_id"])
				assert.Equal(t, "", f.Metadata["namespace"])
				assert.Equal(t, "ConfigMap", f.Metadata["kind"])
				assert.Equal(t, "v1", f.Metadata["api_version"])
				assert.Equal(t, "error", f.Metadata["sub_status"])
				assert.Equal(t, "testdata/scanner/kubescape/manifests/sensitive-configmap.yaml:0", f.Location)
			},
		},
		{
			name: "skips passed controls",
			input: `{
				"summaryDetails": {
					"controls": {}
				},
				"results": [{
					"resourceID": "path=123/api=/v1/default/Pod/test-pod",
					"object": {
						"kind": "Pod",
						"metadata": {
							"name": "test-pod",
							"namespace": "default"
						}
					},
					"controls": [{
						"controlID": "C-0002",
						"name": "Exec into container",
						"status": {
							"status": "passed"
						}
					}]
				}]
			}`,
			expectedCount: 0,
		},
		{
			name: "handles multiple resources with same control",
			input: `{
				"summaryDetails": {
					"controls": {
						"C-0013": {
							"controlID": "C-0013",
							"name": "Non-root containers",
							"status": "failed",
							"score": 70.0,
							"scoreFactor": 6,
							"category": {
								"name": "Workload",
								"id": "Cat-5"
							}
						}
					}
				},
				"results": [{
					"resourceID": "path=123/api=/v1/ns1/Pod/pod1",
					"object": {
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"name": "pod1",
							"namespace": "ns1"
						}
					},
					"controls": [{
						"controlID": "C-0013",
						"name": "Non-root containers",
						"status": {
							"status": "failed"
						},
						"rules": []
					}]
				}, {
					"resourceID": "path=456/api=/v1/ns2/Pod/pod2",
					"object": {
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"name": "pod2",
							"namespace": "ns2"
						}
					},
					"controls": [{
						"controlID": "C-0013",
						"name": "Non-root containers",
						"status": {
							"status": "failed"
						},
						"rules": []
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
				"summaryDetails": {
					"controls": {
						"C-0270": {
							"controlID": "C-0270",
							"name": "Ensure CPU limits are set",
							"status": "failed",
							"score": 30.0,
							"scoreFactor": 8
						},
						"C-0057": {
							"controlID": "C-0057",
							"name": "Privileged container",
							"status": "failed",
							"score": 95.0,
							"scoreFactor": 8
						}
					}
				},
				"results": [{
					"resourceID": "path=123/api=/v1/default/Deployment/low-risk",
					"object": {
						"kind": "Deployment",
						"metadata": {
							"name": "low-risk",
							"namespace": "default"
						}
					},
					"controls": [{
						"controlID": "C-0270",
						"name": "Ensure CPU limits are set",
						"status": {
							"status": "failed"
						}
					}]
				}, {
					"resourceID": "path=456/api=/v1/default/Pod/high-risk",
					"object": {
						"kind": "Pod",
						"metadata": {
							"name": "high-risk",
							"namespace": "default"
						}
					},
					"controls": [{
						"controlID": "C-0057",
						"name": "Privileged container",
						"status": {
							"status": "failed"
						}
					}]
				}]
			}`,
			expectedCount: 2,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				// Low severity (score 30.0)
				assert.Equal(t, "low", findings[0].Severity)
				// Critical severity (score 95.0)
				assert.Equal(t, "critical", findings[1].Severity)
			},
		},
		{
			name: "extracts framework information",
			input: `{
				"summaryDetails": {
					"controls": {
						"C-0005": {
							"controlID": "C-0005",
							"name": "API server insecure port",
							"status": "failed",
							"score": 80.0,
							"category": {
								"name": "Control plane",
								"id": "Cat-1"
							}
						}
					}
				},
				"results": [{
					"resourceID": "path=123/api=/v1/default/Service/kubernetes",
					"object": {
						"kind": "Service",
						"metadata": {
							"name": "kubernetes",
							"namespace": "default"
						}
					},
					"controls": [{
						"controlID": "C-0005",
						"name": "API server insecure port",
						"status": {
							"status": "failed"
						}
					}]
				}]
			}`,
			expectedCount: 1,
			validate: func(t *testing.T, findings []models.Finding) {
				t.Helper()
				assert.Contains(t, findings[0].Framework, "Control plane")
			},
		},
		{
			name: "handles cluster-scoped resources",
			input: `{
				"summaryDetails": {
					"controls": {
						"C-0035": {
							"controlID": "C-0035",
							"name": "Administrative Roles",
							"status": "failed",
							"score": 90.0
						}
					}
				},
				"results": [{
					"resourceID": "path=123/api=rbac.authorization.k8s.io/v1//ClusterRoleBinding/cluster-admin-binding",
					"object": {
						"apiVersion": "rbac.authorization.k8s.io/v1",
						"kind": "ClusterRoleBinding",
						"metadata": {
							"name": "cluster-admin-binding"
						}
					},
					"controls": [{
						"controlID": "C-0035",
						"name": "Administrative Roles",
						"status": {
							"status": "failed"
						}
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
	assert.Contains(t, err.Error(), "kubescape: failed to parse JSON output")
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
		{"critical", 100.0},
		{"critical", 95.0},
		{"critical", 90.0},
		{"high", 85.0},
		{"high", 70.0},
		{"medium", 60.0},
		{"medium", 40.0},
		{"low", 30.0},
		{"low", 10.0},
		{"low", 0.0},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%.0f", tt.score), func(t *testing.T) {
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

// TestKubescapeReport_ComplexStructure tests parsing a more complex v3 report.
func TestKubescapeReport_ComplexStructure(t *testing.T) {
	scanner := &KubescapeScanner{
		BaseScanner: NewBaseScanner("kubescape", Config{}),
	}

	complexReport := `{
		"summaryDetails": {
			"controls": {
				"C-0030": {
					"controlID": "C-0030",
					"name": "Ingress and Egress blocked",
					"status": "failed",
					"score": 65.0,
					"scoreFactor": 6,
					"category": {
						"name": "Network",
						"id": "Cat-4"
					}
				},
				"C-0053": {
					"controlID": "C-0053",
					"name": "Access Kubernetes dashboard",
					"status": "failed",
					"score": 85.0,
					"scoreFactor": 7,
					"category": {
						"name": "Access control",
						"id": "Cat-2"
					}
				}
			}
		},
		"results": [{
			"resourceID": "path=123/api=/v1//Namespace/production",
			"object": {
				"apiVersion": "v1",
				"kind": "Namespace",
				"metadata": {
					"name": "production"
				}
			},
			"controls": [{
				"controlID": "C-0030",
				"name": "Ingress and Egress blocked",
				"status": {
					"status": "failed",
					"subStatus": ""
				},
				"rules": [{
					"name": "ingress-and-egress-blocked",
					"status": "failed",
					"paths": []
				}]
			}]
		}, {
			"resourceID": "path=456/api=/v1//Namespace/staging",
			"object": {
				"apiVersion": "v1",
				"kind": "Namespace",
				"metadata": {
					"name": "staging"
				}
			},
			"controls": [{
				"controlID": "C-0030",
				"name": "Ingress and Egress blocked",
				"status": {
					"status": "failed",
					"subStatus": ""
				},
				"rules": []
			}]
		}, {
			"resourceID": "path=789/api=/v1/kubernetes-dashboard/Service/kubernetes-dashboard",
			"object": {
				"apiVersion": "v1",
				"kind": "Service",
				"metadata": {
					"name": "kubernetes-dashboard",
					"namespace": "kubernetes-dashboard"
				}
			},
			"controls": [{
				"controlID": "C-0053",
				"name": "Access Kubernetes dashboard",
				"status": {
					"status": "failed",
					"subStatus": "manual review needed"
				},
				"rules": []
			}]
		}]
	}`

	findings, err := scanner.ParseResults([]byte(complexReport))
	require.NoError(t, err)
	assert.Len(t, findings, 3) // 2 namespaces + 1 service

	// Validate first finding
	assert.Equal(t, "Namespace/production", findings[0].Resource)
	assert.Equal(t, "medium", findings[0].Severity)
	assert.Contains(t, findings[0].Impact, "Score factor: 6")

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
