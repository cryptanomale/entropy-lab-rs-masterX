#!/bin/bash
# Run tests relevant to changed files
# Usage: ./scripts/test-changed.sh

BRANCH_NAME=$(git branch --show-current)
TARGET_BRANCH="main"

if [ "$BRANCH_NAME" = "main" ]; then
  TARGET_BRANCH="develop"
fi

echo "🔍 Detecting changes against $TARGET_BRANCH..."

CHANGED_FILES=$(git diff --name-only "$TARGET_BRANCH"...HEAD | grep "\.rs$")

if [ -z "$CHANGED_FILES" ]; then
  echo "✅ No Rust files changed. Skipping tests."
  exit 0
fi

echo "📦 Changed files:"
echo "$CHANGED_FILES"

# Simple heuristic: if any Rust file changed, run unit tests.
# A more advanced version would use 'cargo test --package' based on file location.
echo "🚀 Running unit tests..."
cargo test --lib
