# CI/CD Pipeline Guide

## Overview

This project uses **GitHub Actions** for its Continuous Integration pipeline. The pipeline is optimized for Rust development, featuring parallel test execution (sharding), intelligent caching, and flaky test detection.

## Pipeline Stages

### 1. Fast Checks (`lint`)
-   **Formatting**: Verified with `rustfmt`.
-   **Linting**: Checked with `clippy` (deny warnings).
-   **Security**: Dependency audit via `cargo-audit`.
-   **Time**: ~1-2 minutes.

### 2. Parallel Tests (`test`)
-   **Sharding**: Tests are split into 4 parallel shards using `cargo-nextest`.
-   **Runner**: `ubuntu-latest`.
-   **Time**: <5 minutes per shard (vs 15+ sequential).
-   **Artifacts**: Test failures uploaded for debugging.

### 3. Burn-In (`burn-in`)
-   **Trigger**: Weekly schedule OR commit message containing `[burn-in]`.
-   **Logic**: Runs the full test suite 10 times in a loop.
-   **Purpose**: Detects non-deterministic (flaky) tests.

### 4. GPU Logic Check (`gpu-check`)
-   **Purpose**: Verifies GPU code compiles and keys generates correctly (mock).
-   **Note**: Does not run full GPU performance tests due to CI runner limitations.

## Local Development

### Run Local CI
Mirror the CI pipeline locally before pushing:
```bash
./scripts/ci-local.sh
```

### Run Tests for Changed Files
Run unit tests only for files modified in the current branch:
```bash
./scripts/test-changed.sh
```

### Detect Flakiness
Run the burn-in loop locally:
```bash
./scripts/burn-in.sh 5  # Run 5 iterations
```

## Secrets Configuration
See `docs/ci-secrets-checklist.md` for required secrets.
