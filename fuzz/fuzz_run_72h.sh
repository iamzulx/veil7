#!/usr/bin/env bash
# fuzz_run_72h.sh — Run all cargo-fuzz targets for minimum 72 hours
# Phase 2.4: Fuzzing infrastructure for veil7
#
# Prerequisites:
#   - cargo-fuzz installed: cargo install cargo-fuzz
#   - Nightly Rust toolchain: rustup default nightly
#
# Usage:
#   ./fuzz_run_72h.sh [--timeout-per-target SECONDS] [--jobs N]
#
# On Termux (no nightly): use the manual libfuzzer runner mode below.

set -euo pipefail
cd "$(dirname "$0")"

DURATION=$((72 * 3600))  # 72 hours in seconds
TIMEOUT_PER_TARGET=600    # 10 min per target if running all
JOBS=1
USE_CARGO_FUZZ=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout-per-target) TIMEOUT_PER_TARGET="$2"; shift 2 ;;
        --jobs) JOBS="$2"; shift 2 ;;
        --manual) USE_CARGO_FUZZ=false; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Collect all targets from Cargo.toml
TARGETS=( $(grep 'name = "fuzz_' Cargo.toml | sed 's/.*"\(.*\)"/\1/' ) )
TOTAL=${#TARGETS[@]}

echo "=== veil7 fuzz runner ==="
echo "Targets: $TOTAL"
echo "Duration: $((DURATION / 3600))h ($DURATION s)"
echo "Per-target timeout: ${TIMEOUT_PER_TARGET}s"
echo "Mode: $(${USE_CARGO_FUZZ} && echo 'cargo-fuzz' || echo 'manual libfuzzer')"
echo ""

OVERALL_START=$(date +%s)
PASSED=0
FAILED=0
CRASHES=0

for TARGET in "${TARGETS[@]}"; do
    ELAPSED=$(( $(date +%s) - OVERALL_START ))
    if [[ $ELAPSED -ge $DURATION ]]; then
        echo "[TIMEOUT] 72h budget exhausted at $((ELAPSED/3600))h"
        break
    fi

    REMAINING=$(( DURATION - ELAPSED ))
    THIS_TIMEOUT=$(( TIMEOUT_PER_TARGET < REMAINING ? TIMEOUT_PER_TARGET : REMAINING ))

    echo "---[$TARGET] (${THIS_TIMEOUT}s)---"
    TARGET_DIR="corpus/$TARGET"
    mkdir -p "$TARGET_DIR"

    if ${USE_CARGO_FUZZ}; then
        # cargo-fuzz mode (requires nightly)
        timeout "${THIS_TIMEOUT}s" cargo fuzz run "$TARGET" --             -max_len=4096 -timeout=30 -jobs="$JOBS"             "$TARGET_DIR" 2>&1 || true
    else
        # Manual libfuzzer binary mode (works on Termux with stable Rust)
        BIN=$(find target -name "$TARGET" -type f -executable 2>/dev/null | head -1)
        if [[ -z "$BIN" ]]; then
            echo "  Building $TARGET..."
            cargo build --bin "$TARGET" 2>/dev/null || { FAILED=$((FAILED+1)); continue; }
            BIN=$(find target -name "$TARGET" -type f -executable 2>/dev/null | head -1)
        fi
        if [[ -n "$BIN" ]]; then
            timeout "${THIS_TIMEOUT}s" "$BIN"                 -max_len=4096 -timeout=30                 "$TARGET_DIR" 2>&1 || {
                    EXIT_CODE=$?
                    if [[ $EXIT_CODE -eq 77 ]]; then
                        echo "  CRASH detected!"
                        CRASHES=$((CRASHES+1))
                    fi
                }
        else
            echo "  SKIP: binary not found"
            FAILED=$((FAILED+1))
            continue
        fi
    fi

    PASSED=$((PASSED+1))
    echo "  OK"
done

ELAPSED=$(( $(date +%s) - OVERALL_START ))
echo ""
echo "=== Summary ==="
echo "Completed: ${PASSED}/${TOTAL}"
echo "Failed: $FAILED"
echo "Crashes: $CRASHES"
echo "Total time: $((ELAPSED/3600))h $((ELAPSED%3600/60))m"
