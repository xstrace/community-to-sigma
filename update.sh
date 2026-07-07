#!/bin/bash
#
# Update workflow: pull latest Splunk security_content, convert to Sigma.
#
# Usage:
#   ./update.sh              # full update
#   ./update.sh --no-pull    # skip git pull, just reconvert
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SECURITY_CONTENT_DIR="${SECURITY_CONTENT_DIR:-/tmp/security_content}"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/output}"

# ---------------------------------------------------------------------------
# 1. Ensure security_content repo exists and is up to date
# ---------------------------------------------------------------------------
if [ "${1:-}" != "--no-pull" ]; then
    if [ -d "$SECURITY_CONTENT_DIR/.git" ]; then
        echo "=== Updating security_content ==="
        git -C "$SECURITY_CONTENT_DIR" pull --ff-only
    else
        echo "=== Cloning security_content (depth=1) ==="
        git clone --depth 1 https://github.com/splunk/security_content.git "$SECURITY_CONTENT_DIR"
    fi
    echo "  security_content at: $(git -C "$SECURITY_CONTENT_DIR" rev-parse --short HEAD)"
fi

# ---------------------------------------------------------------------------
# 2. Setup venv if needed
# ---------------------------------------------------------------------------
if [ ! -f "$SCRIPT_DIR/.venv/bin/python" ]; then
    echo "=== Creating virtual environment ==="
    python3 -m venv "$SCRIPT_DIR/.venv"
    "$SCRIPT_DIR/.venv/bin/pip" install -q -r "$SCRIPT_DIR/requirements.txt"
fi

# ---------------------------------------------------------------------------
# 3. Record previous stats for comparison
# ---------------------------------------------------------------------------
PREV_COUNT=0
if [ -f "$SCRIPT_DIR/conversion_report.json" ]; then
    PREV_COUNT=$("$SCRIPT_DIR/.venv/bin/python" -c "
import json
with open('$SCRIPT_DIR/conversion_report.json') as f:
    print(json.load(f)['summary']['converted'])
" 2>/dev/null || echo 0)
fi

# ---------------------------------------------------------------------------
# 4. Run conversion
# ---------------------------------------------------------------------------
echo ""
echo "=== Converting detections → Sigma ==="
"$SCRIPT_DIR/.venv/bin/python" "$SCRIPT_DIR/main.py" \
    --input-dir "$SECURITY_CONTENT_DIR/detections" \
    --macro-dir "$SECURITY_CONTENT_DIR/macros" \
    --output-dir "$OUTPUT_DIR"

# ---------------------------------------------------------------------------
# 5. Show delta
# ---------------------------------------------------------------------------
NEW_COUNT=$("$SCRIPT_DIR/.venv/bin/python" -c "
import json
with open('$SCRIPT_DIR/conversion_report.json') as f:
    print(json.load(f)['summary']['converted'])
" 2>/dev/null || echo 0)

echo ""
echo "=== Delta ==="
echo "  Previous conversions: $PREV_COUNT"
echo "  Current conversions:  $NEW_COUNT"
echo "  Delta:                $((NEW_COUNT - PREV_COUNT))"

echo ""
echo "Done. Sigma rules in: $OUTPUT_DIR"
