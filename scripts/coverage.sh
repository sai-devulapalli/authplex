#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/coverage.sh <coverage-profile> <threshold>
# Example: ./scripts/coverage.sh coverage-unit.out 85

PROFILE="${1:?Usage: coverage.sh <profile> <threshold>}"
THRESHOLD="${2:-85}"

if [ ! -f "$PROFILE" ]; then
    echo "ERROR: Coverage profile '$PROFILE' not found."
    echo "Run 'make test-unit' first."
    exit 1
fi

# Extract total coverage percentage
COVERAGE=$(go tool cover -func="$PROFILE" | grep "total:" | awk '{print $3}' | tr -d '%')

if [ -z "$COVERAGE" ]; then
    echo "ERROR: Could not parse coverage from '$PROFILE'."
    exit 1
fi

# Compare using awk for floating point
PASS=$(awk "BEGIN {print ($COVERAGE >= $THRESHOLD) ? 1 : 0}")

echo "Coverage: ${COVERAGE}% (threshold: ${THRESHOLD}%)"

if [ "$PASS" -eq 0 ]; then
    echo "FAIL: Coverage ${COVERAGE}% is below threshold ${THRESHOLD}%."
    exit 1
fi

echo "PASS: Coverage meets threshold."
