#!/bin/bash
# Run burn-in loop to detect flaky tests
# Usage: ./scripts/burn-in.sh [iterations]

ITERATIONS=${1:-10}

echo "🔥 Running burn-in loop ($ITERATIONS iterations)..."

for ((i=1; i<=ITERATIONS; i++)); do
  echo "  Runs $i/$ITERATIONS"
  if command -v cargo-nextest &> /dev/null; then
      cargo nextest run > /dev/null || { echo "❌ Flakiness detected on run $i"; exit 1; }
  else
      cargo test > /dev/null || { echo "❌ Flakiness detected on run $i"; exit 1; }
  fi
done

echo "✅ Passed $ITERATIONS iterations without failure."
