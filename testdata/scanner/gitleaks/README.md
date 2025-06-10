# Gitleaks Test Data

Generated on: $(date)

## Files Generated:
- git-history-findings.json - Secrets found in git history
- filesystem-findings.json - Secrets found in filesystem scan
- custom-config-findings.json - Scan with custom rules (if applicable)

## Test Repository Contents:
1. AWS credentials (access keys and secret keys)
2. API keys (Stripe, GitHub, Slack)
3. Private SSH keys
4. Database passwords
5. OAuth client secrets
6. JWT secrets
7. Webhook URLs with tokens

## Sample Findings:

### filesystem-findings.json
Total secrets found: 2
- generic-api-key: Detected a Generic API Key, potentially exposing access to various services and sensitive operations. in oauth.json

### git-history-findings.json
Total secrets found: 2
- slack-webhook-url: Discovered a Slack Webhook, which could lead to unauthorized message posting and data leakage in Slack channels. in webhooks.yaml
