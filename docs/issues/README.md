# Issue Tracker - Audit Findings (January 2026)

**Generated**: 2026-01-02  
**Source**: Comprehensive Codebase Audit (`docs/CODEBASE_AUDIT_2026-01.md`)  
**Total Issues**: 5 (3 Critical, 2 High Priority)  

---

## Issue Summary

| ID | Title | Priority | Type | Epic | Effort | Status |
|----|-------|----------|------|------|--------|--------|
| CRITICAL-001 | Missing Data Files Prevent Compilation | 🔴 CRITICAL | Bug | Epic 1 | 1 day | Open |
| CRITICAL-002 | Test Database Files Committed to Repository | 🔴 CRITICAL | Hygiene | N/A | 1 day | Open |
| CRITICAL-003 | Electrum Seed Validation Missing | 🔴 CRITICAL | Bug | Epic 1 | 2 days | Open |
| HIGH-001 | Multi-Path Derivation (BIP44/49/84/86) | 🟡 HIGH | Feature | Epic 1 | 1 week | Open |
| HIGH-002 | Extended Address Index Scanning | 🟡 HIGH | Feature | Epic 1 | 2-3 days | Open |

---

## Critical Issues (Must Fix Before Release)

### CRITICAL-001: Missing Data Files Prevent Compilation
- **File**: [CRITICAL-001-missing-data-files.md](CRITICAL-001-missing-data-files.md)
- **Impact**: Complete build failure
- **Root Cause**: Randstorm fingerprint CSV files missing
- **Quick Fix**: Create placeholder CSV files
- **Long-term Fix**: Runtime data loading with graceful fallback

### CRITICAL-002: Test Database Files Committed
- **File**: [CRITICAL-002-test-database-files.md](CRITICAL-002-test-database-files.md)
- **Impact**: Repository bloat, potential data leakage
- **Files**: 7 `.db` files (~140KB total)
- **Fix**: Update `.gitignore`, `git rm --cached` test DBs
- **Prevention**: Add CI check for committed artifacts

### CRITICAL-003: Electrum Seed Validation Missing
- **File**: [CRITICAL-003-electrum-seed-validation.md](CRITICAL-003-electrum-seed-validation.md)
- **Impact**: False positives in Cake Wallet scanner
- **Root Cause**: No version prefix validation for Electrum seeds
- **Fix**: Add `is_valid_electrum_seed()` validation function
- **Affected**: All Cake Wallet scanner variants

---

## High Priority Issues (Next Sprint)

### HIGH-001: Multi-Path Derivation
- **File**: [HIGH-001-multipath-derivation.md](HIGH-001-multipath-derivation.md)
- **Impact**: Missing 75% of addresses (only checks one BIP path)
- **Solution**: Check BIP44/49/84/86 paths for each seed
- **Note**: Multi-path kernels already exist for Milk Sad and Trust Wallet!
- **Effort**: 1 week (core + scanners + GPU kernels)

### HIGH-002: Extended Address Index Scanning
- **File**: [HIGH-002-extended-address-indices.md](HIGH-002-extended-address-indices.md)
- **Impact**: Missing 95%+ of addresses (only checks index 0)
- **Solution**: Scan indices 0-100 (configurable) per path
- **Optimization**: Perfect for GPU parallelization (~100x speedup)
- **Effort**: 2-3 days (quick win!)

---

## Implementation Priority

### Week 1: Critical Blockers
1. **Day 1**: Fix CRITICAL-001 (placeholder CSVs)
2. **Day 1**: Fix CRITICAL-002 (remove .db files, update .gitignore)
3. **Day 2-3**: Fix CRITICAL-003 (Electrum validation)

### Week 2: High Priority Features
4. **Day 1-2**: Implement HIGH-002 (extended indices)
5. **Day 3-5**: Begin HIGH-001 (multi-path derivation)

### Week 3: Complete High Priority
6. **Day 1-3**: Complete HIGH-001 (GPU kernels, testing)
7. **Day 4-5**: Integration testing, documentation

**Total Estimated Time**: 3 weeks to address all critical + high priority issues

---

## Medium Priority Issues (Not Created Yet)

These were identified in the audit but don't have detailed issue files yet:

### Code Quality
- **MEDIUM-001**: Clean up 13 compilation warnings (1 day)
- **MEDIUM-002**: Add structured logging (replace println!) (2-3 days)
- **MEDIUM-003**: Reduce unwrap() usage in production code (2-3 days)

### Testing
- **MEDIUM-004**: Improve test coverage (property tests, fuzzing) (1 week)
- **MEDIUM-005**: Add code coverage reporting (tarpaulin) (1 day)

### Documentation
- **MEDIUM-006**: Add CHANGELOG.md (1 day)
- **MEDIUM-007**: Create issue templates (1 day)
- **MEDIUM-008**: Publish API docs to docs.rs (2 days)

### Infrastructure
- **MEDIUM-009**: Make OpenCL truly optional at build time (1 week)
- **MEDIUM-010**: Add feature matrix testing to CI (2 days)
- **MEDIUM-011**: Update duplicate dependencies (3 days)

---

## Roadmap Gaps (From Audit Report)

These are larger features from the README roadmap that need epics/stories:

### Not Started (0%)
- **Randstorm/BitcoinJS Scanner** (Epic 1, Stories 1.6-1.10) - PARTIALLY DONE
  - BLOCKER: Missing CSV data files (CRITICAL-001)
  - Status: ~50% complete (PRNGs done, integration incomplete)
  
- **Hashcat Modules** - NO EPIC YET
  - Documentation exists (HASHCAT_MODULES_RECOMMENDED.md)
  - 5-6 modules needed
  - Estimated: 2 weeks per module

- **Trust Wallet iOS minstd_rand0** - NO STORY YET
  - CVE-2024-23660
  - Estimated: 1 week

- **bip3x PCG PRNG Scanner** - STUB EXISTS
  - File: `bip3x.rs` (minimal code)
  - Estimated: 1-2 weeks

- **18/24-word Seed Support** - NO STORY YET
  - Currently only 12-word
  - Estimated: 3-5 days

---

## Epic Coverage Status

Based on `_bmad-output/epics.md`:

| Epic | Total Stories | Complete | In Progress | Not Started | % Complete |
|------|---------------|----------|-------------|-------------|------------|
| 1 - Core Scanning | 7 | 2 | 3 | 2 | ~43% |
| 2 - Browser Fingerprints | 5 | 0 | 2 | 3 | ~20% |
| 3 - CLI Interface | 7 | 5 | 1 | 1 | ~71% |
| 4 - Validation | 6 | 0 | 0 | 6 | 0% |
| 5 - Ethics | 6 | 6 | 0 | 0 | 100% ✅ |
| 6 - Target Intelligence | 6 | 4 | 1 | 1 | ~67% |
| 7 - WGPU | 6 | 0 | 2 | 4 | ~17% |
| **TOTAL** | **43** | **17** | **9** | **17** | **40%** |

**Note**: Overall completion from project-context.md says 19% (8/43 stories). This analysis shows ~40% when counting in-progress work.

---

## How to Use These Issues

### For Developers

1. Read the full audit report: `docs/CODEBASE_AUDIT_2026-01.md`
2. Pick an issue from the list above
3. Read the detailed issue file (e.g., `CRITICAL-001-missing-data-files.md`)
4. Follow the implementation checklist
5. Submit PR referencing the issue ID

### For Project Managers

1. Review this index for priorities
2. Assign issues to developers
3. Track progress using the checklists in each issue
4. Update status in this file

### For GitHub Issues

These markdown files can be converted to GitHub issues:

```bash
# Example: Create GitHub issue from markdown
gh issue create --title "CRITICAL-001: Missing Data Files" \
                --body-file docs/issues/CRITICAL-001-missing-data-files.md \
                --label critical,blocker,build,randstorm
```

---

## Related Documentation

- **Audit Report**: `docs/CODEBASE_AUDIT_2026-01.md`
- **Epics**: `_bmad-output/epics.md`
- **Project Context**: `project-context.md`
- **Roadmap**: `README.md` (Roadmap section)
- **Technical Specs**: `_bmad-output/implementation-artifacts/`

---

**Last Updated**: 2026-01-02  
**Next Review**: After critical issues resolved (2-3 weeks)
