#!/usr/bin/env bash
# Generate real Trivy test data from actual scanner runs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/testdata/scanner/trivy"

echo "=== Generating Trivy Test Data ==="
echo "Output directory: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

# Create temporary directory for test files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# 1. Vulnerable Dockerfile
cat > "$TEMP_DIR/Dockerfile" << 'EOF'
# Using old base image with vulnerabilities
FROM node:12-alpine

# Running as root (security issue)
USER root

# Installing packages without specifying versions
RUN apk add --no-cache curl wget git

# Exposing SSH port
EXPOSE 22

# Hardcoded secrets
ENV API_KEY="secret123"
ENV DATABASE_URL="postgres://user:password@localhost/db"

# Copy everything (might include secrets)
COPY . /app
WORKDIR /app

# Run as root
CMD ["node", "server.js"]
EOF

# 2. Vulnerable package.json
cat > "$TEMP_DIR/package.json" << 'EOF'
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.16.0",
    "lodash": "4.17.11",
    "axios": "0.18.0",
    "minimist": "0.0.8",
    "jquery": "2.2.4",
    "bootstrap": "3.3.7",
    "angular": "1.6.0",
    "react": "16.2.0",
    "webpack": "3.11.0",
    "serialize-javascript": "1.7.0"
  }
}
EOF

# 3. Vulnerable Gemfile
cat > "$TEMP_DIR/Gemfile" << 'EOF'
source 'https://rubygems.org'

gem 'rails', '5.0.0'
gem 'nokogiri', '1.8.0'
gem 'rack', '2.0.1'
gem 'sprockets', '3.7.1'
gem 'actionview', '5.0.0'
EOF

# 4. Vulnerable requirements.txt
cat > "$TEMP_DIR/requirements.txt" << 'EOF'
Django==2.2.0
Flask==0.12.2
requests==2.19.1
urllib3==1.22
PyYAML==3.13
Jinja2==2.10
SQLAlchemy==1.2.0
Pillow==5.2.0
cryptography==2.2.2
paramiko==2.4.1
EOF

# 5. Kubernetes manifest with issues
cat > "$TEMP_DIR/deployment.yaml" << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable
  template:
    metadata:
      labels:
        app: vulnerable
    spec:
      containers:
      - name: app
        image: vulnerable-app:latest
        securityContext:
          privileged: true
          runAsUser: 0
          allowPrivilegeEscalation: true
        env:
        - name: DATABASE_PASSWORD
          value: "hardcoded-password"
EOF

# 6. Terraform with security issues
cat > "$TEMP_DIR/main.tf" << 'EOF'
resource "aws_s3_bucket" "insecure" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

resource "aws_db_instance" "insecure" {
  identifier     = "mydb"
  engine         = "mysql"
  instance_class = "db.t2.micro"
  username       = "admin"
  password       = "changeme123!"
  
  skip_final_snapshot = true
  publicly_accessible = true
  
  # No encryption
  storage_encrypted = false
}
EOF

# 7. Source code with hardcoded secrets
cat > "$TEMP_DIR/app.py" << 'EOF'
import os

# Hardcoded credentials
API_KEY = "sk_live_abcdef123456"
DATABASE_URL = "mysql://root:password123@localhost:3306/production"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def connect_to_database():
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {request.args.get('id')}"
    return execute_query(query)
EOF

echo "Running Trivy scans..."

# 1. Docker image scan
echo "1. Scanning Docker images..."
trivy image node:12 \
  --format json \
  --exit-code 0 \
  --timeout 5m \
  2>/dev/null > "$OUTPUT_DIR/node12-vulnerabilities.json" || true

# 2. Filesystem scan
echo "2. Scanning filesystem..."
trivy fs "$TEMP_DIR" \
  --format json \
  --exit-code 0 \
  --timeout 5m \
  2>/dev/null > "$OUTPUT_DIR/filesystem-vulnerabilities.json" || true

# 3. Configuration scan
echo "3. Scanning configurations..."
trivy config "$TEMP_DIR" \
  --format json \
  --exit-code 0 \
  --timeout 5m \
  2>/dev/null > "$OUTPUT_DIR/config-misconfigurations.json" || true

# 4. Secret scan
echo "4. Scanning for secrets..."
trivy fs "$TEMP_DIR" \
  --scanners secret \
  --format json \
  --exit-code 0 \
  --timeout 5m \
  2>/dev/null > "$OUTPUT_DIR/secret-findings.json" || true

# 5. Comprehensive scan (all scanners)
echo "5. Running comprehensive scan..."
trivy fs "$TEMP_DIR" \
  --scanners vuln,secret,config \
  --format json \
  --exit-code 0 \
  --timeout 5m \
  2>/dev/null > "$OUTPUT_DIR/comprehensive-scan.json" || true

# Create a summary file
echo -e "\n=== Generating Summary ==="
cat > "$OUTPUT_DIR/README.md" << 'EOF'
# Trivy Test Data

Generated on: $(date)

## Files Generated:
- node12-vulnerabilities.json - Vulnerabilities in Node.js 12 image
- filesystem-vulnerabilities.json - Vulnerabilities in dependencies
- config-misconfigurations.json - Configuration issues
- secret-findings.json - Exposed secrets
- comprehensive-scan.json - All findings combined

## Test Files Scanned:
1. Dockerfile with security issues
2. package.json with vulnerable npm packages
3. Gemfile with vulnerable Ruby gems
4. requirements.txt with vulnerable Python packages
5. Kubernetes manifests with misconfigurations
6. Terraform files with security issues
7. Source code with hardcoded secrets

## Sample Findings:
EOF

# Add sample findings to README
for file in "$OUTPUT_DIR"/*.json; do
  if [ -f "$file" ] && [ -s "$file" ]; then
    filename=$(basename "$file")
    echo -e "\n### $filename" >> "$OUTPUT_DIR/README.md"
    
    # Count findings by type
    vuln_count=$(jq '[.Results[]?.Vulnerabilities? | length] | add // 0' "$file" 2>/dev/null || echo "0")
    secret_count=$(jq '[.Results[]?.Secrets? | length] | add // 0' "$file" 2>/dev/null || echo "0")
    misconfig_count=$(jq '[.Results[]?.Misconfigurations? | length] | add // 0' "$file" 2>/dev/null || echo "0")
    
    echo "- Vulnerabilities: $vuln_count" >> "$OUTPUT_DIR/README.md"
    echo "- Secrets: $secret_count" >> "$OUTPUT_DIR/README.md"
    echo "- Misconfigurations: $misconfig_count" >> "$OUTPUT_DIR/README.md"
    
    # Add sample vulnerability
    jq -r '.Results[0]?.Vulnerabilities?[0] | select(.) | "- \(.VulnerabilityID): \(.Title // .Description) (Severity: \(.Severity))"' "$file" 2>/dev/null >> "$OUTPUT_DIR/README.md" || true
  fi
done

echo -e "\n✅ Trivy test data generated successfully!"
echo "📁 Output directory: $OUTPUT_DIR"
echo "📊 Files generated: $(ls -1 "$OUTPUT_DIR"/*.json 2>/dev/null | wc -l)"