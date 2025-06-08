package scanner

import (
	"fmt"

	"github.com/Veraticus/prismatic/pkg/logger"
)

// ScannerFactory creates scanners based on type and configuration.
type ScannerFactory struct {
	clientCfg ClientConfig
	logger    logger.Logger
	outputDir string
	config    Config
	useMock   bool
}

// ClientConfig represents the client configuration needed by scanners.
type ClientConfig interface {
	GetAWSConfig() (profiles []string, regions []string, services []string)
	GetDockerTargets() []string
	GetKubernetesConfig() (contexts []string, namespaces []string)
	GetEndpoints() []string
	GetCheckovTargets() []string
}

// NewScannerFactory creates a new scanner factory.
func NewScannerFactory(config Config, clientCfg ClientConfig, outputDir string, useMock bool) *ScannerFactory {
	return NewScannerFactoryWithLogger(config, clientCfg, outputDir, useMock, logger.GetGlobalLogger())
}

// NewScannerFactoryWithLogger creates a new scanner factory with a custom logger.
func NewScannerFactoryWithLogger(config Config, clientCfg ClientConfig, outputDir string, useMock bool, log logger.Logger) *ScannerFactory {
	return &ScannerFactory{
		config:    config,
		clientCfg: clientCfg,
		outputDir: outputDir,
		useMock:   useMock,
		logger:    log,
	}
}

// CreateScanner creates a scanner of the given type.
func (f *ScannerFactory) CreateScanner(scannerType string) (Scanner, error) {
	if f.useMock {
		return NewMockScannerWithLogger(scannerType, f.config, f.logger), nil
	}

	switch scannerType {
	case "trivy":
		return f.createTrivyScanner()
	case "prowler":
		return f.createProwlerScanner()
	case "kubescape":
		return f.createKubescapeScanner()
	case "nuclei":
		return f.createNucleiScanner()
	case "gitleaks":
		return f.createGitleaksScanner()
	case "checkov":
		return f.createCheckovScanner()
	default:
		return nil, fmt.Errorf("unknown scanner type: %s", scannerType)
	}
}

// createTrivyScanner creates and configures a Trivy scanner.
func (f *ScannerFactory) createTrivyScanner() (Scanner, error) {
	targets := f.clientCfg.GetDockerTargets()
	if len(targets) == 0 {
		f.logger.Warn("No targets configured for Trivy")
		return nil, fmt.Errorf("no Trivy targets configured")
	}
	return NewTrivyScannerWithLogger(f.config, targets, f.logger), nil
}

// createProwlerScanner creates and configures a Prowler scanner.
func (f *ScannerFactory) createProwlerScanner() (Scanner, error) {
	profiles, regions, services := f.clientCfg.GetAWSConfig()
	if len(profiles) == 0 {
		f.logger.Warn("No AWS profiles configured for Prowler")
		return nil, fmt.Errorf("no AWS profiles configured")
	}
	return NewProwlerScannerWithLogger(f.config, profiles, regions, services, f.logger), nil
}

// createKubescapeScanner creates and configures a Kubescape scanner.
func (f *ScannerFactory) createKubescapeScanner() (Scanner, error) {
	contexts, namespaces := f.clientCfg.GetKubernetesConfig()
	if len(contexts) == 0 {
		f.logger.Warn("No Kubernetes contexts configured for Kubescape")
		return nil, fmt.Errorf("no Kubernetes contexts configured")
	}
	return NewKubescapeScannerWithLogger(f.config, contexts, namespaces, f.logger), nil
}

// createNucleiScanner creates and configures a Nuclei scanner.
func (f *ScannerFactory) createNucleiScanner() (Scanner, error) {
	endpoints := f.clientCfg.GetEndpoints()
	if len(endpoints) == 0 {
		f.logger.Warn("No endpoints configured for Nuclei")
		return nil, fmt.Errorf("no endpoints configured")
	}
	return NewNucleiScannerWithLogger(f.config, endpoints, f.logger), nil
}

// createGitleaksScanner creates and configures a Gitleaks scanner.
func (f *ScannerFactory) createGitleaksScanner() (Scanner, error) {
	// Gitleaks scans the current directory by default
	target := f.outputDir
	if target == "" {
		target = "."
	}
	return NewGitleaksScannerWithLogger(f.config, target, f.logger), nil
}

// createCheckovScanner creates and configures a Checkov scanner.
func (f *ScannerFactory) createCheckovScanner() (Scanner, error) {
	targets := f.clientCfg.GetCheckovTargets()
	if len(targets) == 0 {
		f.logger.Warn("No targets configured for Checkov")
		return nil, fmt.Errorf("no Checkov targets configured")
	}
	return NewCheckovScannerWithLogger(f.config, targets, f.logger), nil
}

// ScannerTypeDetector detects which scanners should be used based on configuration.
type ScannerTypeDetector struct {
	hasAWS        bool
	hasDocker     bool
	hasKubernetes bool
	hasEndpoints  bool
}

// NewScannerTypeDetector creates a new scanner type detector.
func NewScannerTypeDetector(cfg ClientConfig) *ScannerTypeDetector {
	profiles, _, _ := cfg.GetAWSConfig()
	contexts, _ := cfg.GetKubernetesConfig()

	return &ScannerTypeDetector{
		hasAWS:        len(profiles) > 0,
		hasDocker:     len(cfg.GetDockerTargets()) > 0,
		hasKubernetes: len(contexts) > 0,
		hasEndpoints:  len(cfg.GetEndpoints()) > 0,
	}
}

// DetectScanners returns which scanner types should be used.
func (d *ScannerTypeDetector) DetectScanners(onlyScanners []string) []string {
	// If specific scanners requested, use only those
	if len(onlyScanners) > 0 {
		return onlyScanners
	}

	// Otherwise, determine based on configuration
	var scanners []string

	if d.hasAWS {
		scanners = append(scanners, "prowler")
	}

	if d.hasDocker {
		scanners = append(scanners, "trivy")
	}

	if d.hasKubernetes {
		scanners = append(scanners, "kubescape")
	}

	if d.hasEndpoints {
		scanners = append(scanners, "nuclei")
	}

	// Always include these if not filtered
	scanners = append(scanners, "gitleaks", "checkov")

	return scanners
}
