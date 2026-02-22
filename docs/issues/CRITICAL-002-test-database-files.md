# CRITICAL-002: Test Database Files Committed to Repository

**Priority**: 🔴 CRITICAL  
**Type**: Repository Hygiene / Security  
**Epic**: N/A (Infrastructure)  
**Estimated Effort**: 1 day  
**Assigned**: TBD  

---

## Problem Statement

Seven test database files (`.db` files) totaling ~140KB are committed to the repository root. These should be excluded via `.gitignore` and removed from git history.

## Files Affected

```
./test_intel_v2.db      (16KB)
./test_final_v4.db      (24KB)
./test_intel_v3.db      (24KB)
./test_heuristics.db    (24KB)
./test_targets.db       (16KB)
./test_targets_v2.db    (16KB)
./crates/temporal-planetarium-lib/data/forensic_targets.db
```

## Impact

- ⚠️ **Repository bloat**: Unnecessary binary files in git history
- ⚠️ **Potential data leakage**: Test DBs may contain sensitive addresses or patterns
- ⚠️ **Confusion**: Unclear if these are required fixtures or temporary artifacts
- ⚠️ **CI overhead**: Cloning repo downloads unnecessary data

## Root Cause

`.gitignore` is missing pattern for `.db` files. Current `.gitignore` only covers:
- `*.csv`
- `*.txt` (with exceptions)
- But NOT `*.db`

## Proposed Solution

### Step 1: Update .gitignore

Add to `.gitignore`:

```gitignore
# Database files (test artifacts)
*.db
!crates/temporal-planetarium-lib/data/schema.db  # Exception if schema needed
/test_*.db  # Explicitly exclude test DBs in root
```

### Step 2: Remove from Git

```bash
# Remove from git tracking (keeps local files)
git rm --cached test_*.db
git rm --cached crates/temporal-planetarium-lib/data/forensic_targets.db

# Commit removal
git add .gitignore
git commit -m "chore: remove test database files from git tracking"
```

### Step 3: Document Test Data Generation

Create `tests/README.md` or update existing documentation:

```markdown
## Test Data Generation

Test databases are generated automatically during test runs. 
To regenerate manually:

```bash
cargo test --test <test_name> -- --ignored
```

DO NOT commit `*.db` files to git.
```

### Step 4: Add to CI (Optional)

Add check in CI to prevent accidental commits:

```yaml
- name: Check for committed test artifacts
  run: |
    if git ls-files | grep -E '\.(db|csv)$'; then
      echo "Error: Test artifacts committed"
      exit 1
    fi
```

## Security Considerations

**Review DB Contents Before Deletion**:

1. Check if databases contain sensitive data:
   ```bash
   sqlite3 test_intel_v2.db "SELECT name FROM sqlite_master WHERE type='table';"
   sqlite3 test_intel_v2.db "SELECT * FROM <table_name> LIMIT 5;"
   ```

2. If sensitive data found:
   - Do NOT push to public repository
   - Consider using `git filter-branch` or `BFG Repo-Cleaner` to remove from history
   - Rotate any credentials/keys if exposed

3. If non-sensitive:
   - Simple `git rm --cached` is sufficient

## Acceptance Criteria

- [ ] `.gitignore` updated to exclude `*.db` files
- [ ] All test `.db` files removed from git tracking
- [ ] Local copies of test DBs preserved (if needed for dev)
- [ ] Documentation added explaining how to regenerate test data
- [ ] CI check added (optional) to prevent future commits
- [ ] Git history cleaned if sensitive data found

## Additional Context

See:
- Audit Report: `docs/CODEBASE_AUDIT_2026-01.md` Section 5.1
- `.gitignore` already excludes `*.csv` and most `*.txt` files

## Labels

`critical`, `security`, `repository-hygiene`, `infrastructure`

## Notes

**Priority Justification**: While not blocking compilation, committed database files represent potential security risk and repository bloat. Should be addressed before next public release.
