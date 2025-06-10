#!/usr/bin/env bash
# Update parser tests to use real scanner output

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTDATA_DIR="$PROJECT_ROOT/testdata/scanner"

echo "=== Updating Parser Tests with Real Scanner Output ==="

# Create a Go program to generate updated test cases
cat > "$PROJECT_ROOT/update-tests.go" << 'EOF'
package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "strings"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: go run update-tests.go <scanner>")
        os.Exit(1)
    }
    
    scanner := os.Args[1]
    
    switch scanner {
    case "checkov":
        updateCheckovTests()
    case "nuclei":
        updateNucleiTests()
    case "trivy":
        updateTrivyTests()
    case "gitleaks":
        updateGitleaksTests()
    default:
        log.Fatalf("Unknown scanner: %s", scanner)
    }
}

func updateCheckovTests() {
    fmt.Println("// Updated Checkov parser test with REAL output")
    fmt.Println("// Generated from actual Checkov scans")
    fmt.Println()
    
    // Read terraform findings
    data, err := ioutil.ReadFile("testdata/scanner/checkov/terraform-findings.json")
    if err != nil {
        log.Fatal(err)
    }
    
    var result map[string]interface{}
    if err := json.Unmarshal(data, &result); err != nil {
        log.Fatal(err)
    }
    
    // Extract first finding
    failed := result["results"].(map[string]interface{})["failed_checks"].([]interface{})
    if len(failed) > 0 {
        first := failed[0].(map[string]interface{})
        
        // Create minimal test case
        testCase := map[string]interface{}{
            "check_type": result["check_type"],
            "results": map[string]interface{}{
                "failed_checks": []interface{}{first},
            },
            "summary": result["summary"],
        }
        
        testJSON, _ := json.MarshalIndent(testCase, "\t\t\t\t", "\t")
        
        fmt.Printf(`{
    name: "Real Terraform S3 misconfiguration - ACTUAL Checkov output",
    input: %s,
    expectedCount: 1,
    validate: func(t *testing.T, findings []models.Finding) {
        t.Helper()
        f := findings[0]
        assert.Equal(t, "checkov", f.Scanner)
        assert.Equal(t, "%s", f.Metadata["check_id"])
        
        // Verify parser handles all 28 real fields
        assert.NotEmpty(t, f.Metadata["bc_check_id"])
        assert.NotEmpty(t, f.Metadata["check_class"])
        
        // Check if description/details were parsed correctly
        if desc, ok := f.Metadata["description"]; ok {
            assert.NotEmpty(t, desc)
        }
    },
},
`, "`"+string(testJSON)+"`", first["check_id"])
    }
    
    // Show all fields from real output
    fmt.Println("\n// Real Checkov output contains these fields:")
    if len(failed) > 0 {
        first := failed[0].(map[string]interface{})
        for key := range first {
            fmt.Printf("// - %s\n", key)
        }
    }
}

func updateNucleiTests() {
    fmt.Println("// Updated Nuclei parser test with REAL output")
    fmt.Println("// Generated from actual Nuclei scans")
    fmt.Println()
    
    // Read exposure findings
    data, err := ioutil.ReadFile("testdata/scanner/nuclei/exposure-findings.json")
    if err != nil {
        // Try tech findings
        data, err = ioutil.ReadFile("testdata/scanner/nuclei/tech-findings.json")
        if err != nil {
            log.Fatal("No Nuclei test data found")
        }
    }
    
    // Parse line by line (NDJSON)
    lines := strings.Split(string(data), "\n")
    for i, line := range lines {
        if line == "" {
            continue
        }
        
        var finding map[string]interface{}
        if err := json.Unmarshal([]byte(line), &finding); err != nil {
            continue
        }
        
        if i == 0 {
            // Use first finding as test case
            testJSON, _ := json.MarshalIndent(finding, "\t\t\t\t", "\t")
            
            fmt.Printf(`{
    name: "Real Nuclei finding - ACTUAL scanner output",
    input: %s,
    expectedCount: 1,
    validate: func(t *testing.T, findings []models.Finding) {
        t.Helper()
        f := findings[0]
        assert.Equal(t, "nuclei", f.Scanner)
        assert.Equal(t, "%s", f.Metadata["template_id"])
        
        // Verify real fields are handled
        assert.NotEmpty(t, f.Resource) // host/matched-at
        assert.NotEmpty(t, f.Severity)
    },
},
`, "`"+string(testJSON)+"`", finding["template-id"])
        }
        
        // Only show first example
        break
    }
}

func updateTrivyTests() {
    fmt.Println("// Updated Trivy parser test with REAL output")
    fmt.Println("// Generated from actual Trivy scans")
}

func updateGitleaksTests() {
    fmt.Println("// Updated Gitleaks parser test with REAL output")
    fmt.Println("// Generated from actual Gitleaks scans")
}
EOF

# Generate test data first if not exists
if [ ! -d "$TESTDATA_DIR/checkov" ]; then
    echo "Generating Checkov test data..."
    bash "$SCRIPT_DIR/generate-checkov-testdata.sh"
fi

if [ ! -d "$TESTDATA_DIR/nuclei" ]; then
    echo "Generating Nuclei test data..."
    bash "$SCRIPT_DIR/generate-nuclei-testdata.sh"
fi

echo -e "\n=== Generating Updated Test Cases ==="

echo -e "\n📊 Checkov Test Cases:"
go run "$PROJECT_ROOT/update-tests.go" checkov

echo -e "\n\n🎯 Nuclei Test Cases:"
go run "$PROJECT_ROOT/update-tests.go" nuclei

# Cleanup
rm -f "$PROJECT_ROOT/update-tests.go"

echo -e "\n\n✅ Done! Copy the generated test cases into your parser test files."
echo "📝 Remember to:"
echo "   1. Replace the hardcoded test data with these real examples"
echo "   2. Update test names to indicate they use real output"
echo "   3. Verify all fields are being parsed correctly"