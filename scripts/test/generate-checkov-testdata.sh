#!/usr/bin/env bash
# Generate real Checkov test data from actual scanner runs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/testdata/scanner/checkov"

echo "=== Generating Checkov Test Data ==="
echo "Output directory: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

# Create test Terraform files with various issues
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# 1. S3 bucket with multiple issues
cat > "$TEMP_DIR/s3.tf" << 'EOF'
resource "aws_s3_bucket" "insecure" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"  # CKV_AWS_20: S3 Bucket has public READ access
}

resource "aws_s3_bucket_public_access_block" "bad" {
  bucket = aws_s3_bucket.insecure.id
  
  block_public_acls       = false  # CKV2_AWS_6: S3 bucket should block public access
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
EOF

# 2. Security group with SSH open to world
cat > "$TEMP_DIR/security_group.tf" << 'EOF'
resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # CKV_AWS_24: Security group allows SSH from 0.0.0.0/0
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
EOF

# 3. IAM policy with wildcard permissions
cat > "$TEMP_DIR/iam.tf" << 'EOF'
resource "aws_iam_policy" "admin_policy" {
  name        = "admin_policy"
  description = "Admin policy with too many permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"         # Bad: wildcard actions
        Resource = "*"         # Bad: wildcard resources
      }
    ]
  })
}

resource "aws_iam_user" "test_user" {
  name = "test-user"
}

resource "aws_iam_user_policy" "test_user_policy" {
  name = "test-user-policy"
  user = aws_iam_user.test_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "*"
      }
    ]
  })
}
EOF

# 4. Dockerfile with issues
cat > "$TEMP_DIR/Dockerfile" << 'EOF'
FROM ubuntu:latest
USER root
RUN apt-get update && apt-get install -y curl wget
EXPOSE 22
CMD ["bash"]
# Missing: HEALTHCHECK
# Issue: Running as root
EOF

# 5. Kubernetes deployment with issues
cat > "$TEMP_DIR/deployment.yaml" << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        ports:
        - containerPort: 80
        securityContext:
          privileged: true
          runAsUser: 0
EOF

# 6. Secrets in code
cat > "$TEMP_DIR/config.py" << 'EOF'
# Application configuration
DATABASE_URL = "postgresql://user:password123@localhost/db"
API_KEY = "sk_live_abcdef123456789"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
EOF

echo "Running Checkov scans..."

# Run Checkov with different configurations
echo "1. Terraform scan..."
checkov -d "$TEMP_DIR" \
  --framework terraform \
  -o json \
  --quiet \
  --compact \
  2>/dev/null > "$OUTPUT_DIR/terraform-findings.json" || true

echo "2. Dockerfile scan..."
checkov -f "$TEMP_DIR/Dockerfile" \
  --framework dockerfile \
  -o json \
  --quiet \
  --compact \
  2>/dev/null > "$OUTPUT_DIR/dockerfile-findings.json" || true

echo "3. Kubernetes scan..."
checkov -f "$TEMP_DIR/deployment.yaml" \
  --framework kubernetes \
  -o json \
  --quiet \
  --compact \
  2>/dev/null > "$OUTPUT_DIR/kubernetes-findings.json" || true

echo "4. Secrets scan..."
checkov -f "$TEMP_DIR/config.py" \
  --framework secrets \
  -o json \
  --quiet \
  --compact \
  2>/dev/null > "$OUTPUT_DIR/secrets-findings.json" || true

echo "5. Combined scan (all frameworks)..."
checkov -d "$TEMP_DIR" \
  -o json \
  --quiet \
  --compact \
  2>/dev/null > "$OUTPUT_DIR/all-findings.json" || true

# Create a summary file
echo -e "\n=== Generating Summary ==="
cat > "$OUTPUT_DIR/README.md" << EOF
# Checkov Test Data

Generated on: $(date)

## Files Generated:
- terraform-findings.json - Terraform security issues
- dockerfile-findings.json - Docker security issues  
- kubernetes-findings.json - Kubernetes security issues
- secrets-findings.json - Exposed secrets
- all-findings.json - Combined scan results

## Sample Findings:
EOF

# Add sample findings to README
for file in "$OUTPUT_DIR"/*.json; do
  if [ -f "$file" ]; then
    filename=$(basename "$file")
    count=$(jq '.results.failed_checks | length' "$file" 2>/dev/null || echo "0")
    echo -e "\n### $filename" >> "$OUTPUT_DIR/README.md"
    echo "Failed checks: $count" >> "$OUTPUT_DIR/README.md"
    
    # Add first finding as example
    jq -r '.results.failed_checks[0] | "- \(.check_id): \(.check_name)"' "$file" 2>/dev/null >> "$OUTPUT_DIR/README.md" || true
  fi
done

echo -e "\n✅ Checkov test data generated successfully!"
echo "📁 Output directory: $OUTPUT_DIR"
echo "📊 Files generated: $(ls -1 "$OUTPUT_DIR"/*.json | wc -l)"