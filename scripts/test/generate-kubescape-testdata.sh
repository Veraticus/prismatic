#!/usr/bin/env bash
# Generate real Kubescape test data from scanning Kubernetes YAML files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/testdata/scanner/kubescape"

echo "=== Generating Kubescape Test Data ==="
echo "Output directory: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR/manifests"

# Create Kubernetes manifests with various security issues

# 1. Privileged pod
cat > "$OUTPUT_DIR/manifests/privileged-pod.yaml" << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: default
spec:
  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      privileged: true  # BAD: Running as privileged
      runAsUser: 0      # BAD: Running as root
      allowPrivilegeEscalation: true
    ports:
    - containerPort: 80
EOF

# 2. Deployment without security context
cat > "$OUTPUT_DIR/manifests/insecure-deployment.yaml" << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: insecure
  template:
    metadata:
      labels:
        app: insecure
    spec:
      # BAD: No securityContext defined
      # BAD: No resource limits
      # BAD: No network policies
      containers:
      - name: app
        image: vulnerable/app:latest  # BAD: Using latest tag
        env:
        - name: DATABASE_PASSWORD
          value: "hardcoded-password"  # BAD: Hardcoded secret
        - name: API_KEY
          value: "sk_live_1234567890"
EOF

# 3. Service with NodePort
cat > "$OUTPUT_DIR/manifests/exposed-service.yaml" << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: exposed-service
spec:
  type: NodePort  # BAD: Exposes service on all nodes
  ports:
  - port: 80
    targetPort: 80
    nodePort: 30080
  selector:
    app: exposed
EOF

# 4. Role with excessive permissions
cat > "$OUTPUT_DIR/manifests/excessive-rbac.yaml" << 'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]  # BAD: Wildcard permissions
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: super-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: super-admin
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
EOF

# 5. ConfigMap with sensitive data
cat > "$OUTPUT_DIR/manifests/sensitive-configmap.yaml" << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  database_url: "postgres://user:password@db:5432/myapp"  # BAD: Password in ConfigMap
  api_token: "token_1234567890abcdef"
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA1234567890abcdefghijklmnop
    -----END RSA PRIVATE KEY-----
EOF

# 6. Pod with hostNetwork and hostPID
cat > "$OUTPUT_DIR/manifests/host-access-pod.yaml" << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: host-access
spec:
  hostNetwork: true  # BAD: Uses host network
  hostPID: true      # BAD: Can see host processes
  hostIPC: true      # BAD: Can access host IPC
  containers:
  - name: debug
    image: busybox
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /      # BAD: Mounts host root filesystem
EOF

# 7. StatefulSet without PodDisruptionBudget
cat > "$OUTPUT_DIR/manifests/statefulset-no-pdb.yaml" << 'EOF'
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: database
spec:
  serviceName: database
  replicas: 3
  selector:
    matchLabels:
      app: database
  template:
    metadata:
      labels:
        app: database
    spec:
      containers:
      - name: postgres
        image: postgres:13
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_PASSWORD
          value: "postgres"  # BAD: Default password
# Missing: PodDisruptionBudget
# Missing: Resource limits
# Missing: Security context
EOF

# 8. Ingress without TLS
cat > "$OUTPUT_DIR/manifests/insecure-ingress.yaml" << 'EOF'
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: insecure-ingress
spec:
  # BAD: No TLS configuration
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 80
EOF

echo "Running Kubescape scans..."

# Function to run kubescape and save output
run_kubescape_scan() {
    local framework="$1"
    local output_file="$2"
    local description="$3"
    
    echo "Running Kubescape scan: $description..."
    
    if kubescape scan framework "$framework" "$OUTPUT_DIR/manifests" \
        --format json \
        --output "$output_file" \
        --verbose=false \
        2>/dev/null; then
        
        # Count findings
        local failed=$(jq '.summaryDetails.frameworks[0].controls[].scoreFactor | select(. < 100) | length' "$output_file" 2>/dev/null | wc -l || echo "0")
        echo "  Found issues in $failed controls"
    else
        echo "  Scan completed (non-zero exit code is normal when issues are found)"
    fi
}

# Run various framework scans
run_kubescape_scan "nsa" "$OUTPUT_DIR/nsa-findings.json" "NSA framework"
run_kubescape_scan "mitre" "$OUTPUT_DIR/mitre-findings.json" "MITRE framework"
run_kubescape_scan "cis-v1.23" "$OUTPUT_DIR/cis-findings.json" "CIS Kubernetes Benchmark"

# Run all frameworks scan
echo "Running comprehensive scan..."
kubescape scan "$OUTPUT_DIR/manifests" \
    --format json \
    --output "$OUTPUT_DIR/all-findings.json" \
    --verbose=false \
    2>/dev/null || true

# Run specific control scans for faster testing
echo "Running specific control scans..."
kubescape scan control "Privileged container" "$OUTPUT_DIR/manifests" \
    --format json \
    --output "$OUTPUT_DIR/privileged-findings.json" \
    2>/dev/null || true

kubescape scan control "Configured liveness probe" "$OUTPUT_DIR/manifests" \
    --format json \
    --output "$OUTPUT_DIR/liveness-findings.json" \
    2>/dev/null || true

# Create summary
echo -e "\n=== Generating Summary ==="
cat > "$OUTPUT_DIR/README.md" << EOF
# Kubescape Test Data

Generated on: $(date)

## Test Manifests Created:
1. **privileged-pod.yaml** - Pod running as privileged with root user
2. **insecure-deployment.yaml** - Deployment without security context
3. **exposed-service.yaml** - Service using NodePort
4. **excessive-rbac.yaml** - ClusterRole with wildcard permissions
5. **sensitive-configmap.yaml** - ConfigMap containing passwords
6. **host-access-pod.yaml** - Pod with host network/PID/IPC access
7. **statefulset-no-pdb.yaml** - StatefulSet without PodDisruptionBudget
8. **insecure-ingress.yaml** - Ingress without TLS

## Scans Performed:
- NSA Kubernetes Hardening Framework
- MITRE ATT&CK Framework
- CIS Kubernetes Benchmark
- All frameworks combined
- Specific control scans (for fast testing)

## Files Generated:
EOF

# Add file summaries
for file in "$OUTPUT_DIR"/*.json; do
    if [ -f "$file" ] && [ -s "$file" ]; then
        filename=$(basename "$file")
        echo "- **$filename**" >> "$OUTPUT_DIR/README.md"
    fi
done

# Download frameworks for offline use
echo -e "\nDownloading frameworks for offline testing..."
mkdir -p "$OUTPUT_DIR/frameworks"
kubescape download framework nsa --output "$OUTPUT_DIR/frameworks/nsa.json" 2>/dev/null || true
kubescape download framework mitre --output "$OUTPUT_DIR/frameworks/mitre.json" 2>/dev/null || true

echo -e "\n## Offline Testing"  >> "$OUTPUT_DIR/README.md"
echo "Frameworks cached in frameworks/ directory for offline use:"  >> "$OUTPUT_DIR/README.md"
echo '```bash'  >> "$OUTPUT_DIR/README.md"
echo 'kubescape scan --use-from frameworks/nsa.json manifests/'  >> "$OUTPUT_DIR/README.md"
echo '```'  >> "$OUTPUT_DIR/README.md"

echo -e "\n✅ Kubescape test data generated successfully!"
echo "📁 Output directory: $OUTPUT_DIR"
echo "📊 Files generated: $(ls -1 "$OUTPUT_DIR"/*.json 2>/dev/null | wc -l)"

# Show sample finding
if [ -s "$OUTPUT_DIR/all-findings.json" ]; then
    echo -e "\n📌 Sample finding:"
    jq '.results[0] | {controlID: .controlID, name: .name, severity: .scoreFactor}' "$OUTPUT_DIR/all-findings.json" 2>/dev/null || echo "Could not parse sample"
fi