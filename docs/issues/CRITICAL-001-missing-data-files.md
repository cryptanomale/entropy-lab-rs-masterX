# CRITICAL-001: Missing Data Files Prevent Compilation

**Priority**: 🔴 CRITICAL / BLOCKER  
**Type**: Bug  
**Epic**: Epic 1 - Core Scanning Engine  
**Estimated Effort**: 1 day  
**Assigned**: TBD  

---

## Problem Statement

The project cannot compile due to missing data files that are referenced via `include_str!()` macros in the Randstorm fingerprints module.

## Error Messages

```
error: couldn't read `crates/temporal-planetarium-lib/src/scans/randstorm/fingerprints/data/phase1_top100.csv`: No such file or directory (os error 2)
error: couldn't read `crates/temporal-planetarium-lib/src/scans/randstorm/fingerprints/data/comprehensive.csv`: No such file or directory (os error 2)
```

## Files Affected

- `crates/temporal-planetarium-lib/src/scans/randstorm/fingerprints/mod.rs`
- Lines using `include_str!("data/phase1_top100.csv")` and `include_str!("data/comprehensive.csv")`

## Impact

- ❌ **Complete build failure** - project cannot compile
- ❌ Blocks all development work
- ❌ Blocks CI/CD pipeline
- ❌ Prevents new contributors from building project

## Root Cause

Randstorm scanner implementation is incomplete. Browser fingerprint data files were either:
1. Never committed (sensitive/proprietary data)
2. Excluded via .gitignore
3. Lost during repository reorganization

## Proposed Solutions

### Option A: Create Placeholder Files (Quick Fix)

Create minimal CSV files with headers only to unblock compilation:

**File**: `crates/temporal-planetarium-lib/src/scans/randstorm/fingerprints/data/phase1_top100.csv`
```csv
browser,version,os,prng_type,fingerprint_id
```

**File**: `crates/temporal-planetarium-lib/src/scans/randstorm/fingerprints/data/comprehensive.csv`
```csv
browser,version,os,platform,arch,user_agent,prng_seed,fingerprint_hash
```

**Pros**: 
- Immediate fix (< 1 hour)
- Unblocks development
- Doesn't break existing code structure

**Cons**: 
- Randstorm scanner won't be functional
- Requires documentation of placeholder status

### Option B: Make Data Loading Runtime (Better Long-term)

Refactor to load CSV at runtime instead of compile-time embedding:

```rust
// Replace:
const EMBEDDED_CSV: &str = include_str!("data/phase1_top100.csv");

// With:
fn load_fingerprints() -> Result<Vec<Fingerprint>> {
    let csv_path = PathBuf::from("data/fingerprints/phase1_top100.csv");
    if !csv_path.exists() {
        return Ok(Vec::new()); // Graceful fallback
    }
    // Load and parse CSV
}
```

**Pros**:
- More flexible (users can provide own data)
- Graceful degradation
- Smaller binary size

**Cons**:
- Requires code refactoring (2-4 hours)
- Changes module API

### Option C: Feature Flag (Most Robust)

Make Randstorm scanner fully optional until data is available:

```toml
[features]
randstorm = []  # Enable Randstorm scanner (requires data files)
```

```rust
#[cfg(feature = "randstorm")]
pub mod randstorm;
```

**Pros**:
- Clean separation
- Users opt-in to incomplete features
- Clear documentation path

**Cons**:
- Most code changes
- Affects CLI subcommands

## Recommended Approach

**Combination of A + B**:

1. **Immediate** (Day 1): Create placeholder CSV files (Option A) to unblock compilation
2. **Short-term** (Week 1): Refactor to runtime loading with graceful fallback (Option B)
3. **Document** clearly that Randstorm requires separate data acquisition

## Acceptance Criteria

- [ ] Project compiles successfully with `cargo build --all-features`
- [ ] CI pipeline passes
- [ ] Documentation updated explaining Randstorm data requirements
- [ ] If using placeholders: README notes Randstorm is non-functional
- [ ] If using runtime loading: Graceful error message when data missing

## Additional Context

See:
- Audit Report: `docs/CODEBASE_AUDIT_2026-01.md` Section 1.1
- Epic 1 Stories 1.6-1.10 for Randstorm implementation
- `_bmad-output/randstorm-implementation-progress.md`

## Labels

`critical`, `blocker`, `build`, `randstorm`, `epic-1`
