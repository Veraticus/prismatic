#!/usr/bin/env bash
# Generate real Gitleaks test data from actual scanner runs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/testdata/scanner/gitleaks"

echo "=== Generating Gitleaks Test Data ==="
echo "Output directory: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

# Create a temporary git repository
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

cd "$TEMP_DIR"
git init -q
git config user.email "test@example.com"
git config user.name "Test User"

# 1. AWS credentials
cat > config.yaml << 'EOF'
aws:
  access_key_id: AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  region: us-east-1
EOF
git add config.yaml
git commit -qm "Add AWS config"

# 2. API keys
cat > .env << 'EOF'
# Application settings
API_KEY=sk_live_abcdef123456789
GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456
SLACK_BOT_TOKEN=xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx
STRIPE_SECRET_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc
EOF
git add .env
git commit -qm "Add environment variables"

# 3. Private keys
cat > id_rsa << 'EOF'
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmno
pqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcd
-----END RSA PRIVATE KEY-----
EOF
git add id_rsa
git commit -qm "Add private key"

# 4. Database credentials
cat > database.py << 'EOF'
import psycopg2

# Database configuration
DB_HOST = "localhost"
DB_USER = "admin"
DB_PASS = "super_secret_password_123!"
DB_NAME = "production"

connection_string = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}"
# Also hardcoded: postgresql://admin:super_secret_password_123!@localhost/production
EOF
git add database.py
git commit -qm "Add database config"

# 5. OAuth tokens
cat > oauth.json << 'EOF'
{
  "google": {
    "client_id": "123456789012-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com",
    "client_secret": "GOCSPX-abcdefghijklmnopqrstuvwx"
  },
  "facebook": {
    "app_id": "1234567890123456",
    "app_secret": "abcdef1234567890abcdef1234567890"
  }
}
EOF
git add oauth.json
git commit -qm "Add OAuth credentials"

# 6. JWT secrets
cat > auth.js << 'EOF'
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'my-super-secret-jwt-key-that-should-be-in-env';
const REFRESH_SECRET = 'another-secret-for-refresh-tokens';

function generateToken(user) {
  return jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
}
EOF
git add auth.js
git commit -qm "Add JWT secrets"

# 7. Webhooks and tokens
cat > webhooks.yaml << 'EOF'
webhooks:
  - url: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
    secret: webhook_secret_123456789
  - url: https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ123456
EOF
git add webhooks.yaml
git commit -qm "Add webhook URLs"

# Run Gitleaks scans
echo "Running Gitleaks scans..."

# 1. Full git history scan
echo "1. Scanning git history..."
gitleaks git . \
  --report-path="$OUTPUT_DIR/git-history-findings.json" \
  --exit-code=0 \
  2>/dev/null || true

# 2. Specific file scan
echo "2. Scanning specific files..."
gitleaks detect \
  --source . \
  --report-path="$OUTPUT_DIR/filesystem-findings.json" \
  --exit-code=0 \
  2>/dev/null || true

# 3. Scan with custom config (if exists)
if [ -f "$PROJECT_ROOT/.gitleaks.toml" ]; then
    echo "3. Scanning with custom config..."
    gitleaks git . \
        --config="$PROJECT_ROOT/.gitleaks.toml" \
        --report-path="$OUTPUT_DIR/custom-config-findings.json" \
        --exit-code=0 \
        2>/dev/null || true
fi

# Create a summary file
echo -e "\n=== Generating Summary ==="
cat > "$OUTPUT_DIR/README.md" << 'EOF'
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
EOF

# Add sample findings to README
for file in "$OUTPUT_DIR"/*.json; do
  if [ -f "$file" ] && [ -s "$file" ]; then
    filename=$(basename "$file")
    count=$(jq '. | length' "$file" 2>/dev/null || echo "0")
    echo -e "\n### $filename" >> "$OUTPUT_DIR/README.md"
    echo "Total secrets found: $count" >> "$OUTPUT_DIR/README.md"
    
    # Add first finding as example
    jq -r '.[0] | "- \(.RuleID): \(.Description) in \(.File)"' "$file" 2>/dev/null >> "$OUTPUT_DIR/README.md" || true
  fi
done

echo -e "\n✅ Gitleaks test data generated successfully!"
echo "📁 Output directory: $OUTPUT_DIR"
echo "📊 Files generated: $(ls -1 "$OUTPUT_DIR"/*.json 2>/dev/null | wc -l)"