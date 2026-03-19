#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# test-submit.sh — Build ah-scan and submit a test scan to the server.
#
# Usage:
#   ./scripts/test-submit.sh <API_KEY> [SCAN_TARGET] [ENDPOINT]
#
# Examples:
#   ./scripts/test-submit.sh your-api-key
#   ./scripts/test-submit.sh your-api-key ~/projects/my-app
#   ./scripts/test-submit.sh your-api-key . http://localhost:3000/api/scans/ingest
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

API_KEY="${1:?Usage: $0 <API_KEY> [SCAN_TARGET] [ENDPOINT]}"
SCAN_TARGET="${2:-.}"
ENDPOINT="${3:-https://verify.agentichighway.ai/api/scans/ingest}"

TIMESTAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
OUT_DIR="test-runs"
OUT_FILE="${OUT_DIR}/${TIMESTAMP}-test.json"

mkdir -p "$OUT_DIR"

echo "═══════════════════════════════════════════════════════"
echo "  ah-scan test-submit"
echo "═══════════════════════════════════════════════════════"
echo "  Target:   $SCAN_TARGET"
echo "  Endpoint: $ENDPOINT"
echo "  Output:   $OUT_FILE"
echo "  Time:     $TIMESTAMP"
echo "═══════════════════════════════════════════════════════"
echo ""

echo "→ Building ah-scan..."
cargo build -p ah-scan 2>&1 | tail -1
echo ""

echo "→ Running scan + submit..."
cargo run -p ah-scan -- repo "$SCAN_TARGET" \
    --contract \
    --out "$OUT_FILE" \
    --submit "$ENDPOINT" \
    --api-key "$API_KEY"

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ Done. Contract saved to $OUT_FILE"
    echo "  Size: $(wc -c < "$OUT_FILE" | tr -d ' ') bytes"
else
    echo "✗ Submission failed (exit $EXIT_CODE)"
fi

exit $EXIT_CODE
