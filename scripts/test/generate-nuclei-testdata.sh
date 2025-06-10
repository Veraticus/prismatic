#!/usr/bin/env bash
# Generate real Nuclei test data from actual scanner runs
# This script uses the newer version with test server - see generate-nuclei-testdata-with-server.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/testdata/scanner/nuclei"

echo "=== Generating Nuclei Test Data ==="
echo "Output directory: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

# Create temporary directory for test files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Create web root with various exposures
WEB_ROOT="$TEMP_DIR/webroot"
mkdir -p "$WEB_ROOT"

# 1. Technology signatures
cat > "$WEB_ROOT/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Test Application</title>
    <meta name="generator" content="WordPress 5.8" />
    <meta http-equiv="X-Powered-By" content="PHP/7.4.3" />
</head>
<body>
    <h1>Welcome to Test Server</h1>
    <!-- Powered by Apache/2.4.41 (Ubuntu) -->
    <div id="wp-admin">Admin Panel</div>
    <script src="/wp-includes/js/jquery/jquery.min.js"></script>
</body>
</html>
EOF

# 2. Git exposure
mkdir -p "$WEB_ROOT/.git"
cat > "$WEB_ROOT/.git/config" << 'EOF'
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
[remote "origin"]
    url = https://github.com/example/private-repo.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[user]
    email = admin@example.com
    name = Admin User
EOF

# 3. Configuration files
cat > "$WEB_ROOT/.env" << 'EOF'
APP_ENV=production
APP_DEBUG=true
APP_KEY=base64:abcdef123456789==
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=myapp
DB_USERNAME=root
DB_PASSWORD=secret123!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF

cat > "$WEB_ROOT/config.json" << 'EOF'
{
    "database": {
        "host": "localhost",
        "username": "admin",
        "password": "admin123",
        "database": "production"
    },
    "api": {
        "key": "sk_live_abcdef123456",
        "secret": "secret_key_here"
    }
}
EOF

# 4. Backup files
cat > "$WEB_ROOT/backup.sql" << 'EOF'
-- MySQL dump
CREATE DATABASE myapp;
USE myapp;
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(255),
    email VARCHAR(100)
);
INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com');
EOF

# 5. Admin panels
mkdir -p "$WEB_ROOT/admin"
cat > "$WEB_ROOT/admin/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Admin Login</title></head>
<body>
    <form action="/admin/login" method="POST">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
</body>
</html>
EOF

# 6. phpinfo exposure
cat > "$WEB_ROOT/phpinfo.php" << 'EOF'
<?php
phpinfo();
?>
EOF

# 7. Directory listing
cat > "$WEB_ROOT/.htaccess" << 'EOF'
Options +Indexes
DirectoryIndex index.html
EOF

# Start a simple HTTP server
echo "Starting test HTTP server..."
cd "$WEB_ROOT"
python3 -m http.server 8888 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 2

# Function to run nuclei and save output
run_nuclei_scan() {
    local tags="$1"
    local output_file="$2"
    local description="$3"
    
    echo "Running Nuclei scan: $description..."
    nuclei -u http://localhost:8888 \
        -tags "$tags" \
        -j \
        -silent \
        -no-color \
        -duc \
        -rl 100 \
        -c 50 \
        -timeout 3 \
        2>/dev/null > "$output_file" || true
    
    # Count findings
    local count=$(grep -c "template-id" "$output_file" 2>/dev/null || echo "0")
    echo "  Found $count issues"
}

# Run various Nuclei scans
run_nuclei_scan "tech" "$OUTPUT_DIR/tech-findings.json" "Technology detection"
run_nuclei_scan "exposure,config" "$OUTPUT_DIR/exposure-findings.json" "Exposures and configs"
run_nuclei_scan "panel" "$OUTPUT_DIR/panel-findings.json" "Admin panels"
run_nuclei_scan "cve" "$OUTPUT_DIR/cve-findings.json" "CVE vulnerabilities"
run_nuclei_scan "misconfiguration" "$OUTPUT_DIR/misconfig-findings.json" "Misconfigurations"

# Combined scan with common tags
echo "Running combined scan..."
nuclei -u http://localhost:8888 \
    -tags "tech,exposure,config,panel,misconfiguration" \
    -severity "info,low,medium,high,critical" \
    -j \
    -silent \
    -no-color \
    -duc \
    -rl 100 \
    -c 50 \
    -timeout 5 \
    2>/dev/null > "$OUTPUT_DIR/all-findings.json" || true

# Stop the server
kill $SERVER_PID 2>/dev/null || true

# Create a summary file
echo -e "\n=== Generating Summary ==="
cat > "$OUTPUT_DIR/README.md" << EOF
# Nuclei Test Data

Generated on: $(date)

## Files Generated:
- tech-findings.json - Technology detection results
- exposure-findings.json - File exposures and config leaks
- panel-findings.json - Admin panel detections
- cve-findings.json - CVE vulnerability scans
- misconfig-findings.json - Misconfiguration detections
- all-findings.json - Combined scan results

## Test Server Contents:
- Git repository exposure (.git/config)
- Environment file (.env)
- Configuration files (config.json)
- Backup files (backup.sql)
- Admin panels (/admin/)
- PHP info disclosure (phpinfo.php)
- Technology signatures (WordPress, Apache, PHP)

## Sample Findings:
EOF

# Add sample findings to README
for file in "$OUTPUT_DIR"/*.json; do
  if [ -f "$file" ] && [ -s "$file" ]; then
    filename=$(basename "$file")
    count=$(grep -c "template-id" "$file" 2>/dev/null || echo "0")
    echo -e "\n### $filename" >> "$OUTPUT_DIR/README.md"
    echo "Total findings: $count" >> "$OUTPUT_DIR/README.md"
    
    # Add first finding as example
    head -1 "$file" | jq -r '. | "- \(.["template-id"]): \(.info.name) (\(.info.severity))"' 2>/dev/null >> "$OUTPUT_DIR/README.md" || true
  fi
done

# Also create a consolidated unique findings file
echo -e "\nCreating consolidated findings file..."
cat "$OUTPUT_DIR"/*.json 2>/dev/null | sort -u > "$OUTPUT_DIR/consolidated-findings.json" || true

echo -e "\n✅ Nuclei test data generated successfully!"
echo "📁 Output directory: $OUTPUT_DIR"
echo "📊 Files generated: $(ls -1 "$OUTPUT_DIR"/*.json | wc -l)"