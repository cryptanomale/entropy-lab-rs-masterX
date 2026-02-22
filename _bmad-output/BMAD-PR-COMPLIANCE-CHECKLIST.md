# BMAD PR Compliance Checklist (Temporal Planetarium)

Use this before opening any PR for Randstorm or other scanners.

## Process
- Confirm Quick-Dev entry followed: project-context loaded, Mode selected (tech-spec or direct), escalation check done.
- Link to spec/architecture: `project-context.md`, `architecture-randstorm-scanner.md`, `randstorm-tech-spec.md`.
- Update workflow tracking if status changed (`_bmad-output/bmm-workflow-status.yaml`).
- Include summary of scope and acceptance criteria in the PR description.

## Code & Security
- No private key materialization or logging on CPU; GPU-only key handling where applicable.
- Error handling: no `unwrap()`/`expect()` on fallible paths; use `anyhow`/`thiserror` patterns as in existing scanners.
- Input validation: reject invalid addresses/CSV rows with clear errors.
- Respect feature flags: GPU optional; CPU fallback must work.

## Quality Gates
- `cargo fmt`
- `cargo clippy -- -D warnings`
- `cargo test` (and relevant `-- --nocapture` where needed)
- GPU path smoke test if hardware available; otherwise CPU parity test.
- Bench/metrics (optional but recommended): record GPU vs CPU seeds/sec if changed.

## Docs & Outputs
- Update or cite relevant docs when behavior changes: `development-guide.md`, `architecture-randstorm-scanner.md`, `randstorm-tech-spec.md`.
- Add/refresh usage examples for new CLI flags or outputs.
- Note responsible-disclosure stance in docs when touching Randstorm logic.

