#!/usr/bin/env bash

# Simple screenshot script using Chrome/Chromium headless

URL="${1:-}"
OUTPUT="${2:-screenshot.png}"
WIDTH="${3:-1200}"
HEIGHT="${4:-800}"

if [ -z "$URL" ]; then
    echo "Usage: $0 <url-or-file> [output] [width] [height]"
    exit 1
fi

# Convert relative paths to absolute file:// URLs
if [[ ! "$URL" =~ ^https?:// ]] && [[ ! "$URL" =~ ^file:// ]]; then
    URL="file://$(realpath "$URL")"
fi

# Try to find Chrome/Chromium
CHROME=""
for cmd in chromium-browser chromium google-chrome google-chrome-stable; do
    if command -v "$cmd" &> /dev/null; then
        CHROME="$cmd"
        break
    fi
done

if [ -z "$CHROME" ]; then
    echo "Error: Chrome/Chromium not found"
    echo "Install with: sudo apt install chromium-browser"
    exit 1
fi

echo "📸 Taking screenshot of: $URL"
echo "   Output: $OUTPUT"

# Take screenshot with Chrome headless
"$CHROME" \
    --headless \
    --disable-gpu \
    --no-sandbox \
    --window-size="${WIDTH},${HEIGHT}" \
    --screenshot="$OUTPUT" \
    --screenshot-full-size \
    "$URL"

echo "✅ Screenshot saved!"