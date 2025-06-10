package scanner

import (
	"fmt"

	"github.com/Veraticus/prismatic/internal/config"
	"github.com/Veraticus/prismatic/pkg/logger"
)

// Factory creates scanners based on type and configuration.
type Factory struct {
	logger          logger.Logger
	clientConfig    *config.Config
	repositoryPaths map[string]string
	outputDir       string
	baseConfig      Config
}

// NewScannerFactory creates a new scanner factory.
func NewScannerFactory(baseConfig Config, clientConfig *config.Config, outputDir string) *Factory {
	return NewScannerFactoryWithLogger(baseConfig, clientConfig, outputDir, logger.GetGlobalLogger())
}

// NewScannerFactoryWithLogger creates a new scanner factory with a custom logger.
func NewScannerFactoryWithLogger(baseConfig Config, clientConfig *config.Config, outputDir string, log logger.Logger) *Factory {
	return &Factory{
		baseConfig:   baseConfig,
		clientConfig: clientConfig,
		outputDir:    outputDir,
		logger:       log,
	}
}

// SetRepositoryPaths sets the repository paths for scanners that need them.
func (f *Factory) SetRepositoryPaths(paths map[string]string) {
	f.repositoryPaths = paths
}

// CreateScanner creates a scanner of the given type.
func (f *Factory) CreateScanner(scannerType string) (Scanner, error) {
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
func (f *Factory) createTrivyScanner() (Scanner, error) {
	if f.clientConfig.Docker == nil || len(f.clientConfig.Docker.Containers) == 0 {
		f.logger.Warn("No targets configured for Trivy")
		return nil, fmt.Errorf("no Docker targets configured for Trivy scanner")
	}
	return NewTrivyScannerWithLogger(f.baseConfig, f.clientConfig.Docker.Containers, f.logger), nil
}

// createProwlerScanner creates and configures a Prowler scanner.
func (f *Factory) createProwlerScanner() (Scanner, error) {
	if f.clientConfig.AWS == nil || len(f.clientConfig.AWS.Profiles) == 0 {
		f.logger.Warn("No AWS profiles configured for Prowler")
		return nil, fmt.Errorf("no AWS profiles configured for Prowler scanner")
	}
	// Note: services array is not in config, passing nil for now
	return NewProwlerScannerWithLogger(f.baseConfig, f.clientConfig.AWS.Profiles, f.clientConfig.AWS.Regions, nil, f.logger), nil
}

// createKubescapeScanner creates and configures a Kubescape scanner.
func (f *Factory) createKubescapeScanner() (Scanner, error) {
	if f.clientConfig.Kubernetes == nil || len(f.clientConfig.Kubernetes.Contexts) == 0 {
		f.logger.Warn("No Kubernetes contexts configured for Kubescape")
		return nil, fmt.Errorf("no Kubernetes contexts configured for Kubescape scanner")
	}
	return NewKubescapeScannerWithLogger(f.baseConfig, f.clientConfig.Kubernetes.Kubeconfig,
		f.clientConfig.Kubernetes.Contexts, f.clientConfig.Kubernetes.Namespaces, f.logger), nil
}

// createNucleiScanner creates and configures a Nuclei scanner.
func (f *Factory) createNucleiScanner() (Scanner, error) {
	if len(f.clientConfig.Endpoints) == 0 {
		f.logger.Warn("No endpoints configured for Nuclei")
		return nil, fmt.Errorf("no web endpoints configured for Nuclei scanner")
	}
	return NewNucleiScannerWithLogger(f.baseConfig, f.clientConfig.Endpoints, f.logger), nil
}

// createGitleaksScanner creates and configures a Gitleaks scanner.
func (f *Factory) createGitleaksScanner() (Scanner, error) {
	// If we have repositories, scan each one
	if len(f.repositoryPaths) > 0 {
		// For now, we'll create a scanner that scans all repositories
		// In the future, we might want to create multiple scanner instances
		return NewGitleaksScannerWithRepositories(f.baseConfig, f.repositoryPaths, f.logger), nil
	}

	// No repositories configured - create scanner with empty target
	// The scanner will detect this and skip execution
	return NewGitleaksScannerWithLogger(f.baseConfig, "", f.logger), nil
}

// createCheckovScanner creates and configures a Checkov scanner.
func (f *Factory) createCheckovScanner() (Scanner, error) {
	// If we have repositories, scan those
	if len(f.repositoryPaths) > 0 {
		targets := make([]string, 0, len(f.repositoryPaths))
		for _, path := range f.repositoryPaths {
			targets = append(targets, path)
		}
		return NewCheckovScannerWithLogger(f.baseConfig, targets, f.logger), nil
	}

	// No repositories configured - create scanner with empty targets
	// The scanner will detect this and skip execution
	targets := []string{}
	return NewCheckovScannerWithLogger(f.baseConfig, targets, f.logger), nil
}
