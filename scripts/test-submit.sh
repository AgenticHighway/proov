#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# test-submit.sh — Build proov and submit a test scan to the server.
#
# Usage:
#   ./scripts/test-submit.sh <API_KEY> [SCAN_TARGET] [ENDPOINT]
#
# Examples:
#   ./scripts/test-submit.sh ah_abc123def456
#   ./scripts/test-submit.sh ah_abc123def456 ~/projects/my-app
#   ./scripts/test-submit.sh ah_abc123def456 . http://localhost:3000/api/scans/ingest
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

API_KEY="${1:?Usage: $0 <API_KEY> [SCAN_TARGET] [ENDPOINT]}"
SCAN_TARGET="${2:-.}"
ENDPOINT="${3:-https://vettd.agentichighway.ai/api/scans/ingest}"

TIMESTAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
OUT_DIR="test-runs"
OUT_FILE="${OUT_DIR}/${TIMESTAMP}-test.json"

mkdir -p "$OUT_DIR"

echo "═══════════════════════════════════════════════════════"
echo "  proov test-submit"
echo "═══════════════════════════════════════════════════════"
echo "  Target:   $SCAN_TARGET"
echo "  Endpoint: $ENDPOINT"
echo "  Output:   $OUT_FILE"
echo "  Time:     $TIMESTAMP"
echo "═══════════════════════════════════════════════════════"
echo ""

echo "→ Building proov..."
cargo build -p proov 2>&1 | tail -1
echo ""

echo "→ Running scan + submit..."
cargo run -p proov -- repo "$SCAN_TARGET" \
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
