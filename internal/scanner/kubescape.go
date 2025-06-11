package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// KubescapeScanner implements Kubernetes security scanning using Kubescape.
type KubescapeScanner struct {
	*BaseScanner
	kubeconfig string
	contexts   []string
	namespaces []string
}

// NewKubescapeScanner creates a new Kubescape scanner instance.
func NewKubescapeScanner(config Config, kubeconfig string, contexts, namespaces []string) *KubescapeScanner {
	return NewKubescapeScannerWithLogger(config, kubeconfig, contexts, namespaces, logger.GetGlobalLogger())
}

// NewKubescapeScannerWithLogger creates a new Kubescape scanner instance with a custom logger.
func NewKubescapeScannerWithLogger(config Config, kubeconfig string, contexts, namespaces []string, log logger.Logger) *KubescapeScanner {
	// Default to current context if none specified
	if len(contexts) == 0 {
		contexts = []string{"current-context"}
	}

	// Expand tilde in kubeconfig path
	if strings.HasPrefix(kubeconfig, "~/") {
		if homeDir, err := os.UserHomeDir(); err == nil {
			kubeconfig = filepath.Join(homeDir, kubeconfig[2:])
		}
	}

	return &KubescapeScanner{
		BaseScanner: NewBaseScannerWithLogger("kubescape", config, log),
		kubeconfig:  kubeconfig,
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

	// Log scan configuration
	if len(s.contexts) > 0 {
		s.logger.Info("Kubescape: Scanning Kubernetes clusters", "count", len(s.contexts), "contexts", s.contexts, "namespaces", s.namespaces, "kubeconfig", s.kubeconfig)
	} else {
		s.logger.Info("Kubescape: No Kubernetes contexts configured, skipping scan")
		result.EndTime = time.Now()
		return result, ErrNoTargets
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

	// Add kubeconfig if specified
	if s.kubeconfig != "" {
		args = append(args, "--kubeconfig", s.kubeconfig)
	}

	// Add context if not current-context
	if kubeContext != "current-context" {
		args = append(args, "--kube-context", kubeContext)
	}

	// Add namespaces if specified
	if len(s.namespaces) > 0 {
		args = append(args, "--include-namespaces", strings.Join(s.namespaces, ","))
	}

	// Execute scan using common helper
	s.logger.Debug("Running Kubescape scan", "context", kubeContext, "args", args)
	output, err := ExecuteScanner(ctx, "kubescape", args, s.config)
	if err != nil {
		return nil, fmt.Errorf("kubescape: failed to scan context %s: %w\nOutput: %s", kubeContext, err, string(output))
	}

	// Read the JSON output file
	// outputFile is a temporary file path we created internally with a timestamp
	jsonOutput, err := os.ReadFile(outputFile) // #nosec G304 - controlled temp file
	if err != nil {
		return nil, fmt.Errorf("kubescape: failed to read output file: %w", err)
	}

	return jsonOutput, nil
}

// ParseResults parses Kubescape JSON output into findings.
func (s *KubescapeScanner) ParseResults(raw []byte) ([]models.Finding, error) {
	var report KubescapeV3Report
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("kubescape: failed to parse JSON output: %w", err)
	}

	var findings []models.Finding

	// Process each resource result
	for _, result := range report.Results {
		// Get resource info from the object
		resourceID := s.extractResourceID(result)

		// Process each control that this resource failed
		for _, control := range result.Controls {
			// Skip passed controls
			if control.Status.Status == "passed" || control.Status.Status == "skipped" {
				continue
			}

			// Get control details from summaryDetails
			controlDetails, ok := report.SummaryDetails.Controls[control.ControlID]
			if !ok {
				// If we can't find control details, use what we have
				controlDetails = &ControlSummary{
					ControlID: control.ControlID,
					Name:      control.Name,
					Score:     5.0, // Default medium severity
				}
			}

			finding := models.NewFinding(
				s.Name(),
				s.mapControlToType(control.ControlID),
				s.formatResourceNameFromID(resourceID),
				"", // Kubescape doesn't provide specific location
			).WithSeverity(s.determineSeverity(control, controlDetails))

			finding.Title = control.Name
			finding.Description = s.formatDescriptionFromControl(control, controlDetails)
			finding.Framework = s.extractFrameworkFromCategory(controlDetails.Category)
			finding.Impact = s.formatImpactFromControl(control, controlDetails)
			finding.Remediation = s.extractRemediation(control)
			finding.References = s.extractReferencesFromControl(control)

			// Add metadata
			finding.Metadata["control_id"] = control.ControlID
			finding.Metadata["namespace"] = resourceID.Namespace
			finding.Metadata["kind"] = resourceID.Kind
			finding.Metadata["api_version"] = resourceID.APIVersion

			if control.Status.SubStatus != "" {
				finding.Metadata["sub_status"] = control.Status.SubStatus
			}

			// Add source path if available
			if result.Object != nil && result.Object.SourcePath != "" {
				finding.Location = result.Object.SourcePath
			}

			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// getVersion gets the Kubescape version.
func (s *KubescapeScanner) getVersion(ctx context.Context) string {
	return GetScannerVersion(ctx, "kubescape", "version", func(output []byte) string {
		// Parse version from output
		version := strings.TrimSpace(string(output))
		if parts := strings.Fields(version); len(parts) > 0 {
			return parts[len(parts)-1] // Usually the last field is the version
		}
		return version
	})
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
		"C-0270": "ensure-cpu-limits",
		"C-0271": "ensure-memory-limits",
	}

	if mappedType, ok := typeMap[controlID]; ok {
		return mappedType
	}

	// Default: use control ID as type
	return strings.ToLower(controlID)
}

// determineSeverity determines severity from control or score.
func (s *KubescapeScanner) determineSeverity(control Control, controlSummary *ControlSummary) string {
	// If control has explicit severity, use it
	if control.Severity != "" {
		return strings.ToLower(control.Severity)
	}

	// Otherwise use score from control summary
	if controlSummary != nil {
		return s.mapScoreToSeverityString(controlSummary.Score)
	}

	// Fallback to control's own score if available
	if control.Score > 0 {
		return s.mapScoreToSeverityString(control.Score)
	}

	return "medium" // Default
}

// mapScoreToSeverityString maps Kubescape score to severity string.
func (s *KubescapeScanner) mapScoreToSeverityString(score float64) string {
	// Kubescape v3 uses score-based severity (0-100)
	switch {
	case score >= 90:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
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

// formatDescriptionFromControl creates a detailed description from control and summary.
func (s *KubescapeScanner) formatDescriptionFromControl(control Control, _ *ControlSummary) string {
	// Use control's description if available
	desc := control.Description
	if desc == "" {
		desc = control.Name
	}

	// Add failed paths information if available
	if len(control.Rules) > 0 {
		for _, rule := range control.Rules {
			if rule.Status == "failed" && len(rule.Paths) > 0 {
				desc += "\n\nFailed checks:"
				for _, path := range rule.Paths {
					if path.FailedPath != "" {
						desc += fmt.Sprintf("\n- %s", path.FailedPath)
					}
				}
				break
			}
		}
	}

	return desc
}

// formatImpactFromControl describes the security impact from control data.
func (s *KubescapeScanner) formatImpactFromControl(control Control, summary *ControlSummary) string {
	impact := fmt.Sprintf("Failed control %s with score %.1f/100. ", control.ControlID, summary.Score)

	if summary.Category != nil && summary.Category.Name != "" {
		impact += fmt.Sprintf("Category: %s. ", summary.Category.Name)
	}

	if summary.ScoreFactor > 0 {
		impact += fmt.Sprintf("Score factor: %d. ", summary.ScoreFactor)
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

// extractFrameworkFromCategory extracts framework from category info.
func (s *KubescapeScanner) extractFrameworkFromCategory(category *Category) string {
	if category == nil || category.Name == "" {
		return "Security Best Practices"
	}
	return category.Name
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

// extractReferencesFromControl extracts reference URLs from control.
func (s *KubescapeScanner) extractReferencesFromControl(control Control) []string {
	refs := []string{}

	// Add Kubescape control documentation
	refs = append(refs, fmt.Sprintf("https://hub.armosec.io/docs/controls/%s", strings.ToLower(control.ControlID)))

	return refs
}

// extractRemediation extracts remediation from control rules.
func (s *KubescapeScanner) extractRemediation(control Control) string {
	// Use control's remediation field if available
	if control.Remediation != "" {
		return control.Remediation
	}

	var remediations []string

	for _, rule := range control.Rules {
		if rule.Status == "failed" && len(rule.Paths) > 0 {
			for _, path := range rule.Paths {
				if path.FixPath.Path != "" && path.FixPath.Value != "" {
					remediations = append(remediations, fmt.Sprintf("Set %s to %s", path.FixPath.Path, path.FixPath.Value))
				}
			}
		}
	}

	if len(remediations) > 0 {
		return "Suggested fixes:\n- " + strings.Join(remediations, "\n- ")
	}

	return "Review and fix the failed security checks for this resource."
}

// extractResourceID extracts resource identification from result.
func (s *KubescapeScanner) extractResourceID(result ResourceResult) ResourceID {
	if result.Object == nil {
		return ResourceID{}
	}

	// Parse resourceID to extract components
	// Format: "path=123/api=v1/namespace/Kind/name" or similar
	parts := strings.Split(result.ResourceID, "/")
	var namespace, kind, name, apiVersion string

	for i, part := range parts {
		switch {
		case strings.HasPrefix(part, "api="):
			apiVersion = strings.TrimPrefix(part, "api=")
		case i == len(parts)-1:
			name = part
		case i == len(parts)-2:
			kind = part
		case i == len(parts)-3 && !strings.Contains(part, "="):
			namespace = part
		}
	}

	// Try to get from object metadata if parsing failed
	if kind == "" && result.Object.Kind != "" {
		kind = result.Object.Kind
	}
	if name == "" && result.Object.Metadata.Name != "" {
		name = result.Object.Metadata.Name
	}
	if namespace == "" && result.Object.Metadata.Namespace != "" {
		namespace = result.Object.Metadata.Namespace
	}
	if apiVersion == "" && result.Object.APIVersion != "" {
		apiVersion = result.Object.APIVersion
	}

	return ResourceID{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		Namespace:  namespace,
	}
}

// formatResourceNameFromID formats a resource name from ResourceID.
func (s *KubescapeScanner) formatResourceNameFromID(resource ResourceID) string {
	if resource.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", resource.Kind, resource.Namespace, resource.Name)
	}
	return fmt.Sprintf("%s/%s", resource.Kind, resource.Name)
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

// KubescapeV3Report represents the Kubescape v3 output format.
type KubescapeV3Report struct {
	SummaryDetails SummaryDetails   `json:"summaryDetails"`
	Resources      []ResourceObject `json:"resources"`
	Results        []ResourceResult `json:"results"`
}

// SummaryDetails contains control summaries.
type SummaryDetails struct {
	Controls   map[string]*ControlSummary `json:"controls"`
	Frameworks []FrameworkSummary         `json:"frameworks"`
}

// ControlSummary contains summary info for a control.
type ControlSummary struct {
	Category    *Category `json:"category"`
	ControlID   string    `json:"controlID"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Score       float64   `json:"score"`
	ScoreFactor int       `json:"scoreFactor"`
}

// Category represents control category.
type Category struct {
	SubCategory *Category `json:"subCategory,omitempty"`
	Name        string    `json:"name"`
	ID          string    `json:"id"`
}

// ResourceObject represents a scanned resource.
type ResourceObject struct {
	Object     *K8sObject `json:"object"`
	ResourceID string     `json:"resourceID"`
}

// K8sObject represents a Kubernetes object.
type K8sObject struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   ObjectMetadata `json:"metadata"`
	SourcePath string         `json:"sourcePath"`
}

// ObjectMetadata represents Kubernetes object metadata.
type ObjectMetadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// ResourceResult represents scan results for a resource.
type ResourceResult struct {
	ResourceID string     `json:"resourceID"`
	Object     *K8sObject `json:"object,omitempty"`
	Controls   []Control  `json:"controls"`
}

// Control represents a control check on a resource.
type Control struct {
	Status      Status  `json:"status"`
	ControlID   string  `json:"controlID"`
	Name        string  `json:"name"`
	Severity    string  `json:"severity,omitempty"`
	Description string  `json:"description,omitempty"`
	Remediation string  `json:"remediation,omitempty"`
	Rules       []Rule  `json:"rules"`
	Score       float64 `json:"score,omitempty"`
}

// Rule represents a specific rule check.
type Rule struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Paths  []Path `json:"paths"`
}

// Path represents a failed path in the resource.
type Path struct {
	ResourceID string  `json:"resourceID"`
	FailedPath string  `json:"failedPath"`
	FixPath    FixPath `json:"fixPath"`
}

// FixPath represents a suggested fix.
type FixPath struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}
