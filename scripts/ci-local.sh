#!/bin/bash
# Mirror CI execution locally
# Usage: ./scripts/ci-local.sh

echo "🔍 Running CI pipeline locally..."

# 1. Lint & Format
echo "🎨 Step 1: Lint & Format"
cargo fmt --all -- --check || { echo "❌ FMT failed"; exit 1; }
cargo clippy --all-targets --all-features -- -D warnings || { echo "❌ CLIPPY failed"; exit 1; }

# 2. Test
echo "🧪 Step 2: Tests"
if command -v cargo-nextest &> /dev/null; then
    cargo nextest run || { echo "❌ TESTS failed"; exit 1; }
else
    cargo test || { echo "❌ TESTS failed"; exit 1; }
fi

# 3. Quick Burn-In (3 iterations)
echo "🔥 Step 3: Burn-In (3 iterations)"
for i in {1..3}; do
  echo "  Iteration $i..."
  if command -v cargo-nextest &> /dev/null; then
      cargo nextest run > /dev/null || { echo "❌ BURN-IN failed"; exit 1; }
  else
      cargo test > /dev/null || { echo "❌ BURN-IN failed"; exit 1; }
  fi
done

echo "✅ Local CI pipeline passed!"
