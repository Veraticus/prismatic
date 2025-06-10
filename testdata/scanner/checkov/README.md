# Checkov Test Data

Generated on: Mon Jun  9 08:33:15 PM PDT 2025

## Files Generated:
- terraform-findings.json - Terraform security issues
- dockerfile-findings.json - Docker security issues  
- kubernetes-findings.json - Kubernetes security issues
- secrets-findings.json - Exposed secrets
- all-findings.json - Combined scan results

## Sample Findings:

### all-findings.json
Failed checks: 0

### dockerfile-findings.json
Failed checks: 4
- CKV_DOCKER_1: Ensure port 22 is not exposed

### kubernetes-findings.json
Failed checks: 20
- CKV_K8S_20: Containers should not run with allowPrivilegeEscalation

### secrets-findings.json
Failed checks: 4
- CKV_SECRET_4: Basic Auth Credentials

### terraform-findings.json
Failed checks: 31
- CKV_AWS_286: Ensure IAM policies does not allow privilege escalation
