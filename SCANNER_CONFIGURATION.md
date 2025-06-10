# Scanner Configuration Guide

This guide helps you understand what each scanner is configured to scan and how to verify they're working properly.

## Expected Scanner Output

When running `prismatic scan`, you should see logging that indicates what each scanner is configured to scan:

### Prowler (AWS Security)
```
INFO msg="Prowler: Scanning AWS profiles" count=1 profiles=["liveworld"] regions=["us-east-1"]
```
- **Expected execution time**: 3-5 minutes (depending on AWS resources)
- **Configuration needed**: AWS profiles and regions in config YAML

### Trivy (Container Security)
```
INFO msg="Trivy: Scanning targets" count=4 targets=[...]
```
- **Expected execution time**: 5-30 seconds per container
- **Configuration needed**: Container images in config YAML

### Kubescape (Kubernetes Security)
```
INFO msg="Kubescape: Scanning Kubernetes clusters" count=1 contexts=["liveworld-eks-nonprod"]
```
- **Expected execution time**: 10-30 seconds
- **Configuration needed**: Kubernetes contexts and kubeconfig path

### Nuclei (Web Vulnerability Scanning)
```
INFO msg="Nuclei: Scanning endpoints" count=4 endpoints=["https://login.liveworld.com/", ...]
```
- **Expected execution time**: 1-5 minutes per endpoint
- **Configuration needed**: Web endpoints in config YAML

### Gitleaks (Secret Detection)
```
INFO msg="Gitleaks: Scanning repositories" count=6
```
- **Expected execution time**: 1-10 seconds per repository
- **Configuration needed**: Git repositories in config YAML

### Checkov (Infrastructure as Code)
```
INFO msg="Checkov: Scanning targets" count=6 targets=[...]
```
- **Expected execution time**: 5-20 seconds per repository
- **Configuration needed**: Git repositories in config YAML (shares with Gitleaks)

## Configuration Issues

### Nuclei Running Too Fast (< 1 second)
**Problem**: The liveworld config uses `web_endpoints` with structured format:
```yaml
web_endpoints:
  - name: login-portal
    url: "https://login.liveworld.com/"
```

**Solution**: Update to use `endpoints` as a simple array:
```yaml
endpoints:
  - "https://login.liveworld.com/"
  - "https://collector.scms.liveworld.com/"
  - "https://modserver.scms.liveworld.com/"
  - "https://quiz.scms.liveworld.com/"
```

### Gitleaks/Checkov Running Too Fast (< 1 second)
**Problem**: No repositories are being cloned
**Solution**: Ensure your repositories are accessible and the Git URLs are correct

## Verifying Scanner Installation

You can verify each scanner is installed:
```bash
prowler --version
trivy --version
kubescape version
nuclei -version
gitleaks version
checkov --version
```

## Running Scanners Manually

To test scanners individually:

```bash
# Nuclei
nuclei -u "https://example.com" -j -duc -severity info,low,medium,high,critical

# Gitleaks
gitleaks detect --source=. --report-format=json --exit-code=0

# Trivy
trivy image alpine:latest --format=json

# Prowler
prowler aws --profile default --region us-east-1 --output-formats json

# Kubescape
kubescape scan framework nsa --format json

# Checkov
checkov -d . --output json
```

## Scanner Skip Messages

When a scanner has no targets configured, it will be skipped with messages like:
- "Nuclei: No endpoints configured, skipping scan"
- "Prowler: No AWS profiles configured, skipping scan"
- "Trivy: No targets configured, skipping scan"
- "Kubescape: No contexts configured, skipping scan"