#!/usr/bin/env bash
# Generate real Nuclei test data with an actual test server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/testdata/scanner/nuclei"

echo "=== Generating Nuclei Test Data with Test Server ==="
echo "Output directory: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

# Create a Go test server that simulates various vulnerabilities
cat > "$OUTPUT_DIR/test-server.go" << 'EOF'
package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
)

func main() {
    // Technology detection endpoints
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
        w.Header().Set("X-Powered-By", "PHP/7.4.3")
        w.Header().Set("X-AspNet-Version", "4.0.30319")
        w.WriteHeader(http.StatusOK)
        fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Test Application - Prismatic Scanner Test</title>
    <meta name="generator" content="WordPress 5.8.1" />
    <meta name="description" content="Test server for Nuclei scanning" />
</head>
<body>
    <h1>Welcome to Test Server</h1>
    <!-- Powered by Apache/2.4.41 -->
    <div id="wp-content">
        <p>This is a test server for security scanning.</p>
    </div>
    <script src="/wp-includes/js/jquery/jquery.min.js?ver=3.6.0"></script>
</body>
</html>`)
    })

    // Git exposure
    http.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/plain")
        fmt.Fprintf(w, `[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[remote "origin"]
    url = https://github.com/example/private-repo.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
    remote = origin
    merge = refs/heads/master
[user]
    email = developer@example.com
    name = Developer Name`)
    })

    // Environment file exposure
    http.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/plain")
        fmt.Fprintf(w, `APP_NAME=VulnerableApp
APP_ENV=production
APP_KEY=base64:4K7Xl1xqJzLxP2U3mVkYqP5pYKDTkvNpVJcY4o4DMGE=
APP_DEBUG=true
APP_URL=http://localhost

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=vulnerable_app
DB_USERNAME=root
DB_PASSWORD=SuperSecret123!

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=RedisPass456
REDIS_PORT=6379

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1

MAIL_USERNAME=apikey
MAIL_PASSWORD=SG.abcdefghijklmnop.qrstuvwxyz123456789`)
    })

    // Backup file exposure
    http.HandleFunc("/backup.zip", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/zip")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("PK\x03\x04")) // ZIP file signature
    })

    http.HandleFunc("/database.sql", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/plain")
        fmt.Fprintf(w, `-- MySQL dump 10.13
CREATE DATABASE production;
USE production;
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(255),
    password VARCHAR(255),
    api_key VARCHAR(255)
);
INSERT INTO users VALUES (1, 'admin', 'admin123', 'sk_live_abcdef123456');`)
    })

    // Configuration file exposures
    http.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        fmt.Fprintf(w, `{
    "database": {
        "host": "localhost",
        "username": "admin",
        "password": "DbPass123!",
        "database": "production"
    },
    "api": {
        "key": "sk_live_4242424242424242",
        "secret": "whsec_abcdefghijklmnopqrstuvwxyz123456"
    },
    "aws": {
        "access_key": "AKIAIOSFODNN7EXAMPLE",
        "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
}`)
    })

    // PHP info disclosure
    http.HandleFunc("/phpinfo.php", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, `<html>
<head><title>phpinfo()</title></head>
<body>
<h1>PHP Version 7.4.3</h1>
<table>
<tr><td>System</td><td>Linux server 5.4.0-42-generic</td></tr>
<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
<tr><td>Virtual Directory Support</td><td>disabled</td></tr>
<tr><td>Configuration File (php.ini) Path</td><td>/etc/php/7.4/apache2</td></tr>
<tr><td>Loaded Configuration File</td><td>/etc/php/7.4/apache2/php.ini</td></tr>
</table>
</body>
</html>`)
    })

    // Admin panels
    http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Admin Panel - Login</title></head>
<body>
    <h1>Administrator Login</h1>
    <form method="POST" action="/admin/login">
        <input type="text" name="username" placeholder="Username" />
        <input type="password" name="password" placeholder="Password" />
        <button type="submit">Login</button>
    </form>
</body>
</html>`)
    })

    http.HandleFunc("/wp-admin/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>WordPress Admin</title></head>
<body class="login wp-core-ui">
    <div id="login">
        <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
        <form name="loginform" id="loginform" action="/wp-login.php" method="post">
            <p><input type="text" name="log" id="user_login" /></p>
            <p><input type="password" name="pwd" id="user_pass" /></p>
        </form>
    </div>
</body>
</html>`)
    })

    // API endpoints with issues
    http.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Header().Set("Access-Control-Allow-Origin", "*") // CORS misconfiguration
        fmt.Fprintf(w, `[
    {"id": 1, "username": "admin", "email": "admin@example.com", "role": "administrator"},
    {"id": 2, "username": "user", "email": "user@example.com", "role": "user"}
]`)
    })

    // Directory listing
    http.HandleFunc("/uploads/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, `<html>
<head><title>Index of /uploads/</title></head>
<body>
<h1>Index of /uploads/</h1>
<pre>
<a href="../">../</a>
<a href="backup_2023.zip">backup_2023.zip</a>        15-Jan-2023 10:00    5.2M
<a href="config.bak">config.bak</a>              20-Feb-2023 14:30    2.1K
<a href="database_dump.sql">database_dump.sql</a>      01-Mar-2023 09:15   45.3M
<a href="id_rsa">id_rsa</a>                     10-Apr-2023 16:45    1.7K
</pre>
</body>
</html>`)
    })

    // Swagger/API documentation
    http.HandleFunc("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        fmt.Fprintf(w, `{
    "swagger": "2.0",
    "info": {
        "title": "Vulnerable API",
        "version": "1.0.0"
    },
    "paths": {
        "/api/v1/admin": {
            "get": {
                "description": "Admin endpoint - no authentication required",
                "responses": {"200": {"description": "Success"}}
            }
        }
    }
}`)
    })

    // GraphQL introspection
    http.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Query().Get("query") == "{__schema{types{name}}}" {
            w.Header().Set("Content-Type", "application/json")
            fmt.Fprintf(w, `{"data":{"__schema":{"types":[{"name":"User"},{"name":"Admin"},{"name":"Secret"}]}}}`)
        }
    })

    // Spring Boot actuator
    http.HandleFunc("/actuator/health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        fmt.Fprintf(w, `{"status":"UP","components":{"db":{"status":"UP","details":{"database":"MySQL","validationQuery":"SELECT 1"}}}}`)
    })

    // robots.txt with sensitive paths
    http.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/plain")
        fmt.Fprintf(w, `User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /api/internal/
Disallow: /.git/
Disallow: /config/
Disallow: /private/`)
    })

    port := os.Getenv("PORT")
    if port == "" {
        port = "8888"
    }

    log.Printf("Starting test server on port %s...", port)
    log.Fatal(http.ListenAndServe(":"+port, nil))
}
EOF

# Compile and run the test server
echo "Building test server..."
cd "$OUTPUT_DIR"
go build -o test-server test-server.go

echo "Starting test server on port 8888..."
./test-server &
SERVER_PID=$!
sleep 2

# Function to run nuclei with error handling
run_nuclei_scan() {
    local tags="$1"
    local output_file="$2"
    local description="$3"
    
    echo "Running Nuclei scan: $description..."
    
    if nuclei -u http://localhost:8888 \
        -tags "$tags" \
        -j \
        -silent \
        -no-color \
        -duc \
        -rl 100 \
        -c 50 \
        -timeout 5 \
        -severity info,low,medium,high,critical \
        2>/dev/null > "$output_file.tmp"; then
        
        # Filter out empty lines and move to final location
        grep -v '^$' "$output_file.tmp" > "$output_file" 2>/dev/null || true
        rm -f "$output_file.tmp"
        
        # Count findings
        local count=$(grep -c "template-id" "$output_file" 2>/dev/null || echo "0")
        echo "  Found $count issues"
        
        # Show first finding as example
        if [ "$count" -gt 0 ]; then
            echo "  Example: $(head -1 "$output_file" | jq -r '."template-id" + ": " + .info.name' 2>/dev/null || echo "parsing error")"
        fi
    else
        echo "  Error running nuclei (this is normal if no findings match)"
        touch "$output_file" # Create empty file
    fi
}

# Run various Nuclei scans
echo -e "\nRunning Nuclei scans against test server..."

run_nuclei_scan "tech,technologies" "$OUTPUT_DIR/tech-findings.json" "Technology detection"
run_nuclei_scan "exposure,exposures,exposed" "$OUTPUT_DIR/exposure-findings.json" "File exposures"
run_nuclei_scan "config" "$OUTPUT_DIR/config-findings.json" "Configuration exposures"
run_nuclei_scan "panel,panels" "$OUTPUT_DIR/panel-findings.json" "Admin panels"
run_nuclei_scan "api" "$OUTPUT_DIR/api-findings.json" "API vulnerabilities"
run_nuclei_scan "backup,backups" "$OUTPUT_DIR/backup-findings.json" "Backup files"
run_nuclei_scan "git" "$OUTPUT_DIR/git-findings.json" "Git exposures"
run_nuclei_scan "misc,miscellaneous,misconfiguration" "$OUTPUT_DIR/misc-findings.json" "Misconfigurations"

# Run a comprehensive scan
echo -e "\nRunning comprehensive scan..."
nuclei -u http://localhost:8888 \
    -j \
    -silent \
    -no-color \
    -duc \
    -rl 100 \
    -c 50 \
    -timeout 10 \
    -severity info,low,medium,high,critical \
    2>/dev/null | grep -v '^$' > "$OUTPUT_DIR/all-findings.json" || true

# Create consolidated file
echo -e "\nConsolidating findings..."
cat "$OUTPUT_DIR"/*-findings.json 2>/dev/null | sort -u | grep -v '^$' > "$OUTPUT_DIR/consolidated.json" || true

# Stop the server
echo -e "\nStopping test server..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

# Clean up binary
rm -f "$OUTPUT_DIR/test-server"

# Create summary
echo -e "\n=== Generating Summary ==="
cat > "$OUTPUT_DIR/README.md" << EOF
# Nuclei Test Data

Generated on: $(date)

## Test Server Details

The test server simulated various vulnerabilities and exposures:
- Technology signatures (Apache, PHP, WordPress)
- Git repository exposure (/.git/config)
- Environment file exposure (/.env)
- Backup files (backup.zip, database.sql)
- Configuration files (config.json)
- PHP info disclosure (/phpinfo.php)
- Admin panels (/admin, /wp-admin/)
- API endpoints with CORS issues
- Directory listing (/uploads/)
- API documentation (swagger.json)
- GraphQL introspection
- Spring Boot actuator endpoints

## Files Generated:
EOF

# Add file summaries
total_findings=0
for file in "$OUTPUT_DIR"/*.json; do
    if [ -f "$file" ] && [ -s "$file" ]; then
        filename=$(basename "$file")
        count=$(grep -c "template-id" "$file" 2>/dev/null || echo "0")
        total_findings=$((total_findings + count))
        
        if [ "$count" -gt 0 ]; then
            echo "- **$filename**: $count findings" >> "$OUTPUT_DIR/README.md"
            
            # Add first few findings as examples
            echo "  - Examples:" >> "$OUTPUT_DIR/README.md"
            head -3 "$file" | while IFS= read -r line; do
                if [ -n "$line" ]; then
                    template=$(echo "$line" | jq -r '."template-id"' 2>/dev/null || echo "unknown")
                    name=$(echo "$line" | jq -r '.info.name' 2>/dev/null || echo "unknown")
                    severity=$(echo "$line" | jq -r '.info.severity' 2>/dev/null || echo "unknown")
                    echo "    - $template: $name ($severity)" >> "$OUTPUT_DIR/README.md"
                fi
            done
        fi
    fi
done

echo -e "\n**Total findings across all scans**: $total_findings" >> "$OUTPUT_DIR/README.md"

echo -e "\n✅ Nuclei test data generated successfully!"
echo "📁 Output directory: $OUTPUT_DIR"
echo "📊 Total findings: $total_findings"
echo "📄 Files generated: $(ls -1 "$OUTPUT_DIR"/*.json 2>/dev/null | wc -l)"

# Show sample finding
if [ -s "$OUTPUT_DIR/consolidated.json" ]; then
    echo -e "\n📌 Sample finding:"
    head -1 "$OUTPUT_DIR/consolidated.json" | jq '.' 2>/dev/null || echo "Could not parse sample"
fi