#!/usr/bin/env bash
# view-report.sh - Open the latest report in a browser

set -euo pipefail

# Find the latest report
REPORT_DIR="reports"
if [ ! -d "$REPORT_DIR" ]; then
    echo "No reports directory found"
    exit 1
fi

# Get the most recent HTML file
LATEST_REPORT=$(ls -t "$REPORT_DIR"/*.html 2>/dev/null | head -n1)

if [ -z "$LATEST_REPORT" ]; then
    echo "No HTML reports found"
    exit 1
fi

echo "Opening report: $LATEST_REPORT"

# Try to open in browser based on OS
if command -v xdg-open &> /dev/null; then
    xdg-open "$LATEST_REPORT"
elif command -v open &> /dev/null; then
    open "$LATEST_REPORT"
elif command -v start &> /dev/null; then
    start "$LATEST_REPORT"
else
    echo "Could not detect browser command. Please open manually:"
    echo "file://$(pwd)/$LATEST_REPORT"
fi