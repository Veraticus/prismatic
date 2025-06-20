// Package trivy implements a native Trivy scanner using the streaming architecture.
package trivy

import "time"

// TrivyTechnical contains Trivy-specific technical details for a finding.
type TrivyTechnical struct {
	LastModified     *time.Time        `json:"last_modified,omitempty"`
	PublishedDate    *time.Time        `json:"published_date,omitempty"`
	VendorSeverity   map[string]string `json:"vendor_severity,omitempty"`
	CVSS             CVSSDetails       `json:"cvss,omitempty"`
	Layer            LayerInfo         `json:"layer,omitempty"`
	FixedVersion     string            `json:"fixed_version,omitempty"`
	CheckID          string            `json:"check_id,omitempty"`
	ScannerType      string            `json:"scanner_type"`
	PackageType      string            `json:"package_type,omitempty"`
	PackagePath      string            `json:"package_path,omitempty"`
	SecretType       string            `json:"secret_type,omitempty"`
	Package          string            `json:"package,omitempty"`
	Match            string            `json:"match,omitempty"`
	CVE              string            `json:"cve,omitempty"`
	Class            string            `json:"class,omitempty"`
	Target           string            `json:"target"`
	InstalledVersion string            `json:"installed_version,omitempty"`
	CheckTitle       string            `json:"check_title,omitempty"`
	CheckType        string            `json:"check_type,omitempty"`
	CheckSeverity    string            `json:"check_severity,omitempty"`
	CheckDescription string            `json:"check_description,omitempty"`
	CheckRemediation string            `json:"check_remediation,omitempty"`
	RuleID           string            `json:"rule_id,omitempty"`
	Lines            []LineInfo        `json:"lines,omitempty"`
	CheckReferences  []string          `json:"check_references,omitempty"`
	CWE              []string          `json:"cwe,omitempty"`
	References       []string          `json:"references,omitempty"`
	Code             CodeDetails       `json:"code,omitempty"`
}

// CVSSDetails contains CVSS scoring information.
type CVSSDetails struct {
	V2Vector string  `json:"v2_vector,omitempty"`
	V3Vector string  `json:"v3_vector,omitempty"`
	V2Score  float32 `json:"v2_score,omitempty"`
	V3Score  float32 `json:"v3_score,omitempty"`
}

// LayerInfo contains container image layer information.
type LayerInfo struct {
	Digest string `json:"digest,omitempty"`
	DiffID string `json:"diff_id,omitempty"`
}

// LineInfo contains line number information for findings.
type LineInfo struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// CodeDetails contains code context for misconfigurations.
type CodeDetails struct {
	Lines     []string `json:"lines,omitempty"`
	StartLine int      `json:"start_line"`
	EndLine   int      `json:"end_line"`
}

// TrivyResult represents the JSON structure from Trivy CLI output.
type TrivyResult struct {
	ArtifactName  string              `json:"ArtifactName"`
	ArtifactType  string              `json:"ArtifactType"`
	Results       []TrivyTargetResult `json:"Results"`
	Metadata      TrivyMetadata       `json:"Metadata,omitempty"`
	SchemaVersion int                 `json:"SchemaVersion"`
}

// TrivyMetadata contains metadata about the scan.
type TrivyMetadata struct {
	OS          *TrivyOS       `json:"OS,omitempty"`
	ImageConfig map[string]any `json:"ImageConfig,omitempty"`
	ImageID     string         `json:"ImageID,omitempty"`
	DiffIDs     []string       `json:"DiffIDs,omitempty"`
	RepoTags    []string       `json:"RepoTags,omitempty"`
	RepoDigests []string       `json:"RepoDigests,omitempty"`
	Size        int64          `json:"Size,omitempty"`
}

// TrivyOS contains operating system information.
type TrivyOS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

// TrivyTargetResult represents results for a specific target.
type TrivyTargetResult struct {
	Target            string                  `json:"Target"`
	Class             string                  `json:"Class,omitempty"`
	Type              string                  `json:"Type,omitempty"`
	Vulnerabilities   []TrivyVulnerability    `json:"Vulnerabilities,omitempty"`
	Misconfigurations []TrivyMisconfiguration `json:"Misconfigurations,omitempty"`
	Secrets           []TrivySecret           `json:"Secrets,omitempty"`
}

// TrivyVulnerability represents a vulnerability finding.
type TrivyVulnerability struct {
	Layer            *TrivyLayer         `json:"Layer,omitempty"`
	LastModifiedDate *time.Time          `json:"LastModifiedDate,omitempty"`
	PublishedDate    *time.Time          `json:"PublishedDate,omitempty"`
	CVSS             map[string]CVSSInfo `json:"CVSS,omitempty"`
	DataSource       map[string]any      `json:"DataSource,omitempty"`
	PrimaryURL       string              `json:"PrimaryURL,omitempty"`
	PkgPath          string              `json:"PkgPath,omitempty"`
	SeveritySource   string              `json:"SeveritySource,omitempty"`
	VulnerabilityID  string              `json:"VulnerabilityID"`
	FixedVersion     string              `json:"FixedVersion,omitempty"`
	Title            string              `json:"Title,omitempty"`
	Description      string              `json:"Description,omitempty"`
	Severity         string              `json:"Severity"`
	InstalledVersion string              `json:"InstalledVersion"`
	PkgName          string              `json:"PkgName"`
	PkgID            string              `json:"PkgID,omitempty"`
	CweIDs           []string            `json:"CweIDs,omitempty"`
	References       []string            `json:"References,omitempty"`
}

// TrivyLayer contains layer information.
type TrivyLayer struct {
	Digest string `json:"Digest"`
	DiffID string `json:"DiffID"`
}

// CVSSInfo contains CVSS scoring information from different sources.
type CVSSInfo struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float32 `json:"V2Score,omitempty"`
	V3Score  float32 `json:"V3Score,omitempty"`
}

// TrivyMisconfiguration represents a misconfiguration finding.
type TrivyMisconfiguration struct {
	Layer         *TrivyLayer         `json:"Layer,omitempty"`
	CauseMetadata *TrivyCauseMetadata `json:"CauseMetadata,omitempty"`
	Resolution    string              `json:"Resolution"`
	Title         string              `json:"Title"`
	Description   string              `json:"Description"`
	Message       string              `json:"Message"`
	Type          string              `json:"Type"`
	Severity      string              `json:"Severity"`
	PrimaryURL    string              `json:"PrimaryURL,omitempty"`
	Status        string              `json:"Status"`
	AVDID         string              `json:"AVDID,omitempty"`
	ID            string              `json:"ID"`
	References    []string            `json:"References,omitempty"`
}

// TrivyCauseMetadata contains metadata about the cause of a misconfiguration.
type TrivyCauseMetadata struct {
	Code      *TrivyCodeLines `json:"Code,omitempty"`
	Resource  string          `json:"Resource,omitempty"`
	Provider  string          `json:"Provider,omitempty"`
	Service   string          `json:"Service,omitempty"`
	StartLine int             `json:"StartLine,omitempty"`
	EndLine   int             `json:"EndLine,omitempty"`
}

// TrivyCodeLines contains code context.
type TrivyCodeLines struct {
	Lines []TrivyCodeLine `json:"Lines,omitempty"`
}

// TrivyCodeLine represents a single line of code.
type TrivyCodeLine struct {
	Content     string `json:"Content"`
	Annotation  string `json:"Annotation,omitempty"`
	Highlighted string `json:"Highlighted,omitempty"`
	Number      int    `json:"Number"`
	IsCause     bool   `json:"IsCause"`
	Truncated   bool   `json:"Truncated,omitempty"`
	FirstCause  bool   `json:"FirstCause,omitempty"`
	LastCause   bool   `json:"LastCause,omitempty"`
}

// TrivySecret represents a secret finding.
type TrivySecret struct {
	Layer     *TrivyLayer `json:"Layer,omitempty"`
	RuleID    string      `json:"RuleID"`
	Category  string      `json:"Category"`
	Severity  string      `json:"Severity"`
	Title     string      `json:"Title"`
	Match     string      `json:"Match"`
	Code      TrivyCode   `json:"Code,omitempty"`
	StartLine int         `json:"StartLine"`
	EndLine   int         `json:"EndLine"`
}

// TrivyCode contains code context for secrets.
type TrivyCode struct {
	Lines []TrivyCodeLine `json:"Lines,omitempty"`
}
