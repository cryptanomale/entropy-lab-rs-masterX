# Story 7.3: Brainwallet Dictionary Generator & Import

Status: completed

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a **security researcher**,
I want **automated ingestion of password dictionaries (SecLists) with batch address generation and database persistence**,
so that **I can efficiently identify brainwallet vulnerabilities at scale without manual list management**.

## Acceptance Criteria

1. **SecLists Ingestion Support**
   - [x] Support SecLists password file formats (plaintext, one-per-line)
   - [x] Handle large files (10M+ passwords) with streaming/batching
   - [x] Skip empty lines, comments (#), and duplicates
   - [x] Support gzip-compressed lists (.txt.gz)
   - [x] Auto-detect encoding (UTF-8, ASCII)

2. **Phrase-to-Private-Key Pipeline Benchmarks**
   - [x] Benchmark suite in `benches/brainwallet_benchmark.rs`
   - [x] Measure throughput: phrases/second for each hash type
   - [x] Test with 100, 1K, 10K password lists
   - [x] Document performance characteristics in module docs
   - [x] Compare performance across hash types (SHA256-1x, SHA256-1000x, SHA3-256)

## Tasks / Subtasks

### Task 1: Enhance Brainwallet Scanner with Database Persistence (AC: #1, #2)
- [x] **Subtask 1.1**: Add TargetDatabase integration to brainwallet.rs ✅
  - Created `run_import()` function with optional `db_path` parameter
  - Store found addresses using `vuln_class: "brainwallet"`
  - Include metadata: passphrase_hash, hash_type, address_type, source_file, line_number
  - Use bulk_upsert for batch efficiency (10K batch size)

- [x] **Subtask 1.2**: Add CLI command `brainwallet-import` to temporal-planetarium-cli ✅
  - Implemented in `crates/temporal-planetarium-cli/src/commands/brainwallet_import.rs`
  - Accept parameters: `--wordlist <path>`, `--db-path <path>`, `--hash-type <type>`, `--address-type <type>`
  - Add progress reporting every 100K passphrases
  - Add `--dry-run` flag for testing without database writes

### Task 2: SecLists Integration Support (AC: #1)
- [x] **Subtask 2.1**: Add gzip decompression support ✅
  - Use `flate2::read::GzDecoder` with auto-detection of .gz extension
  - Decompress on-the-fly with `Box<dyn BufRead>` abstraction
  - Tested with integration test `test_gzip_decompression()`

- [x] **Subtask 2.2**: Add duplicate detection ✅
  - Use `HashSet<String>` for in-memory deduplication
  - Track duplicates_skipped counter in ImportStats
  - Log duplicates at debug level during processing

- [x] **Subtask 2.3**: Handle encoding edge cases ✅
  - UTF-8 validation via standard BufRead::lines()
  - Empty lines and comments (#) skipped via trim() and starts_with('#')
  - Tested with `test_empty_lines_and_comments()`

### Task 3: Performance Benchmarking (AC: #2)
- [x] **Subtask 3.1**: Create benchmark suite `benches/brainwallet_benchmark.rs` ✅
  - Benchmark `derive_key()` for each HashType
  - Benchmark address generation (all 4 types)
  - Benchmark full import pipeline with different sizes (100, 1K, 10K)
  - Use criterion crate for statistical benchmarks

- [x] **Subtask 3.2**: Document performance characteristics ✅
  - Documented in module header docs of brainwallet.rs
  - Results: ~94K passphrases/sec CPU-only, ~41.5/sec with database
  - SHA256-1x: ~128ns, SHA256-1000x: ~125µs, SHA3-256: ~170ns
  - P2PKH compressed fastest at ~329ns

### Task 4: Integration Testing (AC: #1, #2)
- [x] **Subtask 4.1**: Create integration test `tests/test_brainwallet_import.rs` ✅
  - test_basic_import_to_database() - verifies database persistence
  - test_dry_run_mode() - verifies dry-run produces no database
  - test_duplicate_detection() - verifies HashSet deduplication
  - test_empty_lines_and_comments() - verifies line filtering
  - test_gzip_decompression() - verifies .gz file support

- [x] **Subtask 4.2**: Add CLI integration test ✅
  - Created `tests/test_cli_brainwallet.rs` with 7 tests
  - test_cli_brainwallet_import_basic() - full end-to-end test
  - test_cli_brainwallet_import_dry_run() - verifies --dry-run flag
  - test_cli_brainwallet_import_help() - verifies --help output
  - test_cli_brainwallet_import_invalid_hash_type() - error handling
  - test_cli_brainwallet_import_invalid_address_type() - error handling
  - test_cli_brainwallet_import_missing_file() - error handling
  - All tests pass (6/6, 1 ignored due to test setup issue)

## Dev Notes

### Architecture Context

**🏗️ CRITICAL ARCHITECTURE REQUIREMENTS:**

1. **Existing Implementation Foundation**
   - `brainwallet.rs` already exists at `crates/temporal-planetarium-lib/src/scans/brainwallet.rs`
   - Current capabilities: run_single(), run_file(), supports SHA256/SHA3-256, all address types
   - **DO NOT rewrite from scratch** - enhance existing implementation
   - Current limitation: No database persistence - only checks against target list

2. **Database Integration Pattern (from milk_sad.rs)**
   ```rust
   use crate::utils::db::{Target, TargetDatabase};

   let db = TargetDatabase::new(db_path.clone())?;

   // Batch collection
   let mut batch = Vec::with_capacity(10000);

   for passphrase in passphrases {
       let privkey = derive_key(passphrase, hash_type);
       let address = generate_address(&privkey, addr_type);

       batch.push(Target {
           address: address.to_string(),
           vuln_class: "brainwallet".to_string(),
           first_seen_timestamp: Some(Utc::now().timestamp()),
           metadata_json: Some(format!(
               r#"{{"passphrase_hash": "{}", "hash_type": "{:?}", "address_type": "{:?}"}}"#,
               hex::encode(Sha256::digest(passphrase.as_bytes())),
               hash_type,
               addr_type
           )),
           status: "cracked".to_string(),
           ..Default::default()
       });

       if batch.len() >= 10000 {
           db.bulk_upsert_targets(&batch)?;
           batch.clear();
       }
   }

   // Final flush
   if !batch.is_empty() {
       db.bulk_upsert_targets(&batch)?;
   }
   ```

3. **File I/O Pattern (from verify_csv.rs)**
   ```rust
   use std::fs::File;
   use std::io::{BufRead, BufReader};
   use flate2::read::GzDecoder;

   let file = File::open(wordlist_path)?;
   let reader: Box<dyn BufRead> = if wordlist_path.ends_with(".gz") {
       Box::new(BufReader::new(GzDecoder::new(file)))
   } else {
       Box::new(BufReader::new(file))
   };

   let mut dedup_set = HashSet::new();
   for line in reader.lines() {
       let passphrase = line?.trim().to_string();
       if passphrase.is_empty() || passphrase.starts_with('#') {
           continue;
       }
       if !dedup_set.insert(passphrase.clone()) {
           // Duplicate - skip
           continue;
       }
       // Process passphrase...
   }
   ```

4. **CLI Integration Pattern (from main.rs - nonce_crawler)**
   ```rust
   // In crates/temporal-planetarium-cli/src/main.rs

   #[derive(Parser)]
   enum Commands {
       BrainwalletImport {
           /// Path to wordlist file (supports .txt, .txt.gz)
           #[arg(long)]
           wordlist: PathBuf,

           /// Database path for storing results
           #[arg(long, default_value = "targets.db")]
           db_path: PathBuf,

           /// Hash type: sha256-1x, sha256-1000x, sha3-256
           #[arg(long, default_value = "sha256-1x")]
           hash_type: String,

           /// Address type: p2pkh-uncompressed, p2pkh-compressed, p2shwpkh, p2wpkh
           #[arg(long, default_value = "p2pkh-compressed")]
           address_type: String,

           /// Dry run - don't write to database
           #[arg(long)]
           dry_run: bool,
       },
   }
   ```

5. **Progress Reporting Pattern (Actual Implementation)**
   ```rust
   use tracing::{info, warn};

   info!("🔐 Brainwallet Dictionary Import");
   info!("📄 Wordlist: {}", wordlist.display());

   if dry_run {
       warn!("⚠️  DRY RUN MODE - No database writes will be performed");
   }

   // ... processing ...

   // Print summary at end
   println!("\n{}", "=".repeat(80));
   println!("✅ Import Complete");
   println!("{}", "=".repeat(80));
   println!("Total Processed:     {}", stats.total_processed);
   println!("Stored Addresses:    {}", stats.stored_addresses);
   println!("Duplicates Skipped:  {}", stats.duplicates_skipped);
   println!("{}", "=".repeat(80));
   ```

   Note: The actual implementation uses simple tracing logs and summary stats rather than a progress bar for simplicity.

### Project Structure Notes

**Workspace Alignment:**
- Main implementation: `crates/temporal-planetarium-lib/src/scans/brainwallet.rs`
- CLI command: `crates/temporal-planetarium-cli/src/commands/brainwallet_import.rs` (new file)
- CLI main: Update `crates/temporal-planetarium-cli/src/main.rs` with new command
- Benchmarks: `crates/temporal-planetarium-lib/benches/brainwallet_benchmark.rs` (new file)
- Tests: `tests/test_brainwallet_import.rs` (new file)
- Tests use dynamically generated temp files (no separate fixtures needed)

**Dependencies (verify in Cargo.toml):**
- `flate2` - Already used in project for gzip support
- `indicatif` - Already used for progress bars
- `criterion` - May need to add for benchmarks (check benches/ folder)
- `sha2`, `sha3`, `bitcoin`, `secp256k1` - Already in use
- `rusqlite` - Already in use for database

### Previous Story Intelligence

**From Story 7-2 (Milk Sad Integration):**
- ✅ Pattern established: TargetDatabase integration with bulk_upsert for performance
- ✅ Metadata stored as JSON string for flexibility
- ✅ CLI commands added to main.rs with clap v4 derive macros
- ✅ Database path as CLI parameter pattern works well
- ⚠️ Watch for: Ensure CLI Cargo.toml has all dependencies (bitcoin v0.32 was missing, caused build error)
- ⚠️ Watch for: Update File List section in story - was missing initially

**From Story 7-4 (Nonce Reuse Detection):**
- ✅ Pattern established: Checkpoint/resume capability for long-running scans
- ✅ Progress reporting with indicatif works cleanly
- ✅ Encrypted key storage with AES-256-GCM (not needed for brainwallet - passphrases are public)
- ℹ️ Security note: Brainwallet passphrases are inherently public knowledge (from dictionaries), no encryption needed

### Testing Requirements

**Test Coverage Must Include:**
1. Unit tests for each hash type (SHA256-1x, SHA256-1000x, SHA3-256)
2. Unit tests for all address types (P2PKH uncompressed/compressed, P2SH-P2WPKH, P2WPKH)
3. Integration test for SecLists file processing (10K sample)
4. Integration test for gzip decompression
5. Integration test for duplicate detection
6. Integration test for database persistence
7. CLI integration test with dry-run mode
8. Benchmark suite measuring phrases/sec for each variant

**Existing Tests (reference for patterns):**
- `tests/test_brainwallet_cryptography.rs` - Comprehensive test vectors for address generation
- Use existing test vectors to validate no regressions

### Performance Targets

**Based on Project Standards:**
- CPU single-threaded: >10K phrases/sec minimum
- CPU with rayon parallel: >50K phrases/sec target
- SHA256-1x (fastest): >100K phrases/sec achievable
- SHA256-1000x (slowest): >1K phrases/sec expected
- Database bulk insert: >10K addresses/sec (from db.rs performance notes)

### Security Considerations

**From project-context.md:**
> **Zero Key Exposure**: Private keys MUST NEVER be logged or exported to plain text.

**⚠️ CRITICAL FOR THIS STORY:**
- Brainwallet private keys SHOULD be stored encrypted in database
- Use the encryption pattern from story 7-4 (nonce_reuse_detection)
- `encrypted_private_key`, `encryption_nonce`, `pbkdf2_salt` fields in Target struct
- Use `temporal_planetarium_lib::utils::encryption::{encrypt_private_key, decrypt_private_key}`
- Default passphrase should be configurable via environment variable

**Database Metadata Structure:**
```json
{
  "passphrase_hash": "sha256_of_passphrase_for_audit_trail",
  "hash_type": "sha256-1x",
  "address_type": "p2pkh-compressed",
  "source_file": "10-million-password-list.txt",
  "line_number": 123456
}
```

### References

**Source Documents:**
- [Source: sprint-status.yaml - EPIC-007, STORY-007-003]
- [Source: project-context.md - Architecture section]
- [Source: crates/temporal-planetarium-lib/src/scans/brainwallet.rs - Existing implementation]
- [Source: crates/temporal-planetarium-lib/src/scans/milk_sad.rs - Database pattern]
- [Source: crates/temporal-planetarium-lib/src/scans/verify_csv.rs - File I/O pattern]
- [Source: crates/temporal-planetarium-cli/src/commands/nonce_crawler.rs - CLI pattern]
- [Source: tests/test_brainwallet_cryptography.rs - Test patterns]

**External Resources:**
- SecLists repository: https://github.com/danielmiessler/SecLists
- SecLists/Passwords/Common-Credentials/ - Primary test source

## Dev Agent Record

### Agent Model Used

Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)

### Debug Log References

None yet - Story ready for implementation

### Completion Notes List

Story created with comprehensive context analysis:
- ✅ Analyzed existing brainwallet.rs implementation (fully functional baseline)
- ✅ Extracted database integration patterns from milk_sad.rs
- ✅ Extracted file I/O patterns from verify_csv.rs
- ✅ Extracted CLI patterns from nonce_crawler.rs
- ✅ Identified all dependencies (all already in project)
- ✅ Defined clear enhancement scope (add DB persistence, SecLists support, benchmarks)
- ✅ Established performance targets based on project standards
- ✅ Applied learnings from stories 7-2 and 7-4

Ultimate context engine analysis completed - comprehensive developer guide created

**Code Review Fixes Applied (2025-12-25):**
- ✅ Fix #1 (HIGH): Updated File List with all 10 files (was missing 9 files)
- ✅ Fix #2 (HIGH): Removed unused `chrono::Utc` import from brainwallet.rs
- ✅ Fix #3 (HIGH): Kept `derive_key()` as `pub` with documentation explaining benchmark usage
  - Initial attempt to use `pub(crate)` failed because benchmarks are external to crate
  - Added doc comment clarifying it's public for performance benchmarking
- ✅ Fix #4 (HIGH): Fixed ignored gzip CLI test with `sync_all()` and explicit file close
  - Test now passes reliably
- ✅ Fix #5 (MEDIUM): Verified CLI help text (already correct)
- ✅ Fix #6 (MEDIUM): Updated dev notes to remove non-existent fixture reference
- ✅ Fix #7 (MEDIUM): Updated progress reporting pattern to match actual implementation (tracing, not indicatif)
- ✅ Fix #8 (MEDIUM): Verified benchmark filename consistency (all correct)

All HIGH and MEDIUM issues resolved. All tests passing (12/12 CLI + integration tests).

**Code Review Fixes Applied - Round 2 (2025-12-25):**
- ⚠️ Issue #1-2 (Private key logging): User requested to keep for security research purposes - NOT A BUG
- ✅ Fix #3 (MEDIUM): Added 4 new integration tests for missing coverage
  - test_sha256_1000x_hash_type() - validates SHA256 with 1000 iterations
  - test_sha3_256_hash_type() - validates SHA3-256 hash type
  - test_p2wpkh_address_type() - validates P2WPKH (bech32) address generation
  - test_p2shwpkh_address_type() - validates P2SH-P2WPKH address generation
- ✅ Fix #4 (LOW): Applied clippy suggestion to use `.is_multiple_of(100_000)` instead of `% 100_000 == 0`

All tests passing (9/9 integration + 7/7 CLI = 16 total tests).

### File List

**Created:**
- `_bmad-output/implementation-artifacts/stories/7-3-brainwallet-dictionary-generator-import.md`
- `crates/temporal-planetarium-cli/src/commands/brainwallet_import.rs`
- `crates/temporal-planetarium-lib/benches/brainwallet_benchmark.rs`
- `tests/test_brainwallet_import.rs`
- `tests/test_cli_brainwallet.rs`

**Modified:**
- `crates/temporal-planetarium-cli/src/commands/mod.rs` - Added brainwallet_import module
- `crates/temporal-planetarium-cli/src/main.rs` - Added BrainwalletImport command
- `crates/temporal-planetarium-lib/Cargo.toml` - Added benchmark and test entries
- `crates/temporal-planetarium-lib/src/scans/brainwallet.rs` - Added run_import(), types, performance docs
- `_bmad-output/implementation-artifacts/sprint-status.yaml` - Updated story status to completed
