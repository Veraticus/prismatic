package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/pkg/logger"
)

// KubescapeScanner implements Kubernetes security scanning using Kubescape.
type KubescapeScanner struct {
	*BaseScanner
	contexts   []string
	namespaces []string
}

// NewKubescapeScanner creates a new Kubescape scanner instance.
func NewKubescapeScanner(config Config, contexts, namespaces []string) *KubescapeScanner {
	return NewKubescapeScannerWithLogger(config, contexts, namespaces, logger.GetGlobalLogger())
}

// NewKubescapeScannerWithLogger creates a new Kubescape scanner instance with a custom logger.
func NewKubescapeScannerWithLogger(config Config, contexts, namespaces []string, log logger.Logger) *KubescapeScanner {
	// Default to current context if none specified
	if len(contexts) == 0 {
		contexts = []string{"current-context"}
	}

	return &KubescapeScanner{
		BaseScanner: NewBaseScannerWithLogger("kubescape", config, log),
		contexts:    contexts,
		namespaces:  namespaces,
	}
}

// Scan executes Kubescape against configured Kubernetes clusters.
func (s *KubescapeScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
	startTime := time.Now()

	result := &models.ScanResult{
		Scanner:   s.Name(),
		Version:   s.getVersion(ctx),
		StartTime: startTime,
		Findings:  []models.Finding{},
	}

	// Create output file for results
	outputFile := filepath.Join(s.config.WorkingDir, fmt.Sprintf("kubescape-%d.json", time.Now().Unix()))
	defer func() { _ = os.Remove(outputFile) }() // Clean up

	// Scan each context
	for _, context := range s.contexts {
		if err := ctx.Err(); err != nil {
			result.EndTime = time.Now()
			result.Error = fmt.Sprintf("scan canceled: %v", err)
			return result, nil
		}

		output, err := s.scanContext(ctx, context, outputFile)
		if err != nil {
			// Log error but continue with other contexts
			s.logger.Warn("Kubescape scan failed for context",
				"context", context,
				"error", err)
			continue
		}

		// Parse results
		findings, err := s.ParseResults(output)
		if err != nil {
			s.logger.Warn("Failed to parse Kubescape results",
				"context", context,
				"error", err)
			continue
		}

		result.Findings = append(result.Findings, findings...)
	}

	result.EndTime = time.Now()
	return result, nil
}

// scanContext runs Kubescape against a specific context.
func (s *KubescapeScanner) scanContext(ctx context.Context, kubeContext string, outputFile string) ([]byte, error) {
	args := []string{
		"scan",
		"--format", "json",
		"--output", outputFile,
		"--verbose",
	}

	// Add context if not current-context
	if kubeContext != "current-context" {
		args = append(args, "--kube-context", kubeContext)
	}

	// Add namespaces if specified
	if len(s.namespaces) > 0 {
		args = append(args, "--include-namespaces", strings.Join(s.namespaces, ","))
	}

	// Create command
	cmd := exec.CommandContext(ctx, "kubescape", args...)
	cmd.Dir = s.config.WorkingDir

	// Set timeout
	if s.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(s.config.Timeout)*time.Second)
		defer cancel()
		cmd = exec.CommandContext(ctx, "kubescape", args...)
	}

	// Execute scan
	s.logger.Debug("Running Kubescape scan", "context", kubeContext, "args", args)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s scan failed: failed to scan context %s: %w\nOutput: %s", s.Name(), kubeContext, err, string(output))
	}

	// Read the JSON output file
	// outputFile is a temporary file path we created internally with a timestamp
	jsonOutput, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("%s scan failed: failed to read output file: %w", s.Name(), err)
	}

	return jsonOutput, nil
}

// ParseResults parses Kubescape JSON output into findings.
func (s *KubescapeScanner) ParseResults(raw []byte) ([]models.Finding, error) {
	var report KubescapeReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, NewStructuredError(s.Name(), ErrorTypeParse, err)
	}

	var findings []models.Finding

	// Process each result
	for _, result := range report.Results {
		// Skip passed controls
		if result.Status.Status == "passed" || result.Status.Status == "skipped" {
			continue
		}

		// Process each resource that failed the control
		for _, resource := range result.ResourcesIDs {
			finding := models.NewFinding(
				s.Name(),
				s.mapControlToType(result.ControlID),
				s.formatResourceName(resource),
				"", // Kubescape doesn't provide specific location
			).WithSeverity(s.mapScoreToSeverityString(result.Score))

			finding.Title = result.Name
			finding.Description = s.formatDescription(result)
			finding.Framework = s.extractFramework(result)
			finding.Impact = s.formatImpact(result)
			finding.Remediation = result.Remediation
			finding.References = s.extractReferences(result)

			// Add metadata
			finding.Metadata["control_id"] = result.ControlID
			finding.Metadata["namespace"] = resource.Namespace
			finding.Metadata["kind"] = resource.Kind
			finding.Metadata["api_version"] = resource.APIVersion

			if result.Status.SubStatus != "" {
				finding.Metadata["sub_status"] = result.Status.SubStatus
			}

			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// getVersion gets the Kubescape version.
func (s *KubescapeScanner) getVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "kubescape", "version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse version from output
	version := strings.TrimSpace(string(output))
	if parts := strings.Fields(version); len(parts) > 0 {
		return parts[len(parts)-1] // Usually the last field is the version
	}

	return version
}

// mapControlToType maps Kubescape control IDs to finding types.
func (s *KubescapeScanner) mapControlToType(controlID string) string {
	// Map common control IDs to readable types
	typeMap := map[string]string{
		"C-0001": "forbidden-capabilities",
		"C-0002": "exec-into-container",
		"C-0003": "dangerous-capabilities",
		"C-0004": "resources-limits",
		"C-0005": "api-server-insecure-port",
		"C-0006": "api-server-anonymous-auth",
		"C-0007": "audit-logs-enabled",
		"C-0008": "rbac-enabled",
		"C-0009": "resource-policies",
		"C-0012": "applications-credentials",
		"C-0013": "non-root-containers",
		"C-0014": "immutable-filesystem",
		"C-0015": "registry-allowed",
		"C-0016": "host-pid-ipc",
		"C-0017": "privileged-container",
		"C-0018": "configured-liveness-probe",
		"C-0019": "configured-readiness-probe",
		"C-0020": "mount-service-principal",
		"C-0021": "exposed-sensitive-interfaces",
		"C-0026": "kubernetes-dashboard",
		"C-0030": "ingress-controller-webhook",
		"C-0034": "automatic-mapping-service-account",
		"C-0035": "cluster-admin-binding",
		"C-0038": "host-network",
		"C-0041": "hostpath-volumes",
		"C-0042": "ssh-server-running",
		"C-0044": "container-hostport",
		"C-0045": "writeable-hostpath-mount",
		"C-0046": "insecure-capabilities",
		"C-0048": "dump-sensitive-data",
		"C-0049": "network-policies",
		"C-0050": "resources-cpu-limit",
		"C-0052": "instance-metadata-api",
		"C-0053": "access-kubelet-api",
		"C-0054": "cluster-internal-networking",
		"C-0055": "linux-hardening",
		"C-0056": "configured-security-profiles",
		"C-0057": "administrative-boundaries",
		"C-0058": "security-context-non-root",
		"C-0061": "pods-in-default-namespace",
		"C-0062": "sudo-in-container",
		"C-0063": "portforward-privileges",
		"C-0065": "no-impersonation",
		"C-0066": "secret-kms-encryption",
		"C-0067": "audit-log-maxage",
		"C-0068": "psp-enabled",
		"C-0069": "disable-anonymous-auth",
		"C-0070": "enforce-kubelet-client-tls",
		"C-0073": "naked-pods",
		"C-0074": "containers-read-only-root-filesystem",
		"C-0075": "image-pull-policy-always",
		"C-0076": "label-usage",
		"C-0077": "k8s-common-labels",
		"C-0078": "images-from-allowed-registry",
		"C-0079": "cve-vulnerability-scanner",
		"C-0081": "cve-vulnerability-scanner",
		"C-0083": "cni-plugin-version",
		"C-0084": "unsupported-k8s-version",
		"C-0085": "workloads-with-selinux-options",
		"C-0086": "workloads-with-secrets-as-env-vars",
		"C-0087": "pod-service-account",
		"C-0088": "rbac-cluster-role-binding",
		"C-0089": "rbac-roles",
		"C-0090": "existing-privileged-container-cis",
	}

	if mappedType, ok := typeMap[controlID]; ok {
		return mappedType
	}

	// Default: use control ID as type
	return strings.ToLower(controlID)
}

// mapScoreToSeverityString maps Kubescape score to severity string.
func (s *KubescapeScanner) mapScoreToSeverityString(score float64) string {
	// Kubescape uses score-based severity (0-10)
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	default:
		return "low"
	}
}

// formatResourceName formats a Kubernetes resource identifier.
func (s *KubescapeScanner) formatResourceName(resource ResourceID) string {
	if resource.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", resource.Kind, resource.Namespace, resource.Name)
	}
	return fmt.Sprintf("%s/%s", resource.Kind, resource.Name)
}

// formatDescription creates a detailed description from the control result.
func (s *KubescapeScanner) formatDescription(result KubescapeResult) string {
	desc := result.Description
	if result.Remediation != "" && result.Remediation != desc {
		desc += "\n\nRemediation: " + result.Remediation
	}
	return desc
}

// formatImpact describes the security impact.
func (s *KubescapeScanner) formatImpact(result KubescapeResult) string {
	impact := fmt.Sprintf("Failed control %s with score %.1f/10. ", result.ControlID, result.Score)

	if result.Category != "" {
		impact += fmt.Sprintf("Category: %s. ", result.Category)
	}

	if len(result.RelatedResources) > 0 {
		impact += fmt.Sprintf("Affects %d resources.", len(result.ResourcesIDs))
	}

	return impact
}

// extractFramework extracts compliance framework information.
func (s *KubescapeScanner) extractFramework(result KubescapeResult) string {
	frameworks := []string{}

	// Common framework mappings based on control categories
	if strings.Contains(strings.ToLower(result.Category), "nsa") {
		frameworks = append(frameworks, "NSA")
	}
	if strings.Contains(strings.ToLower(result.Category), "miter") {
		frameworks = append(frameworks, "MITER ATT&CK")
	}
	if strings.Contains(result.ControlID, "C-00") && result.ControlID <= "C-0020" {
		frameworks = append(frameworks, "CIS")
	}

	if len(frameworks) > 0 {
		return strings.Join(frameworks, ", ")
	}

	return result.Category
}

// extractReferences extracts reference URLs.
func (s *KubescapeScanner) extractReferences(result KubescapeResult) []string {
	refs := []string{}

	// Add Kubescape control documentation
	refs = append(refs, fmt.Sprintf("https://hub.armosec.io/docs/controls/%s", strings.ToLower(result.ControlID)))

	// Add any URLs from the description or remediation
	if result.BaseScore > 0 {
		refs = append(refs, fmt.Sprintf("https://hub.armosec.io/docs/controls#%s", strings.ToLower(result.Name)))
	}

	return refs
}

// KubescapeReport represents the overall scan report.
type KubescapeReport struct {
	Kind     string            `json:"kind"`
	Metadata ReportMetadata    `json:"metadata"`
	Summary  Summary           `json:"summary"`
	Results  []KubescapeResult `json:"results"`
}

// ReportMetadata contains scan metadata.
type ReportMetadata struct {
	CreationTime    time.Time `json:"creationTimestamp"`
	Name            string    `json:"name"`
	Namespace       string    `json:"namespace"`
	UID             string    `json:"uid"`
	ResourceVersion string    `json:"resourceVersion"`
}

// Summary contains scan summary statistics.
type Summary struct {
	Frameworks []FrameworkSummary `json:"frameworks"`
}

// FrameworkSummary contains framework-specific summary.
type FrameworkSummary struct {
	Name            string  `json:"name"`
	Version         string  `json:"version"`
	Score           float64 `json:"score"`
	TotalResources  int     `json:"totalResources"`
	FailedResources int     `json:"failedResources"`
	PassedResources int     `json:"passedResources"`
}

// KubescapeResult represents a control check result.
type KubescapeResult struct {
	Status           Status       `json:"status"`
	ControlID        string       `json:"controlID"`
	Name             string       `json:"name"`
	Description      string       `json:"description"`
	Remediation      string       `json:"remediation"`
	Category         string       `json:"category"`
	ResourcesIDs     []ResourceID `json:"resourceIDs"`
	RelatedResources []ResourceID `json:"relatedObjects"`
	Score            float64      `json:"score"`
	BaseScore        float64      `json:"baseScore"`
}

// Status represents the control status.
type Status struct {
	Status    string `json:"status"`
	SubStatus string `json:"subStatus"`
}

// ResourceID identifies a Kubernetes resource.
type ResourceID struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
}
