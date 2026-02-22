# Story 1.1: MWC1616 PRNG Implementation

Status: review

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a **security researcher**,
I want the scanner to exactly replicate Chrome V8's MWC1616 Math.random() algorithm,
so that I can reconstruct the PRNG state used by vulnerable BitcoinJS wallets (2011-2015).

## Acceptance Criteria

1. **Given** a known MWC1616 seed pair (s1, s2)
   **When** the PRNG generates the next random value
   **Then** the output matches the formula: `s1 = 18000 * (s1 & 0xFFFF) + (s1 >> 16)`, `s2 = 30903 * (s2 & 0xFFFF) + (s2 >> 16)`, result = `(s1 << 16) + (s2 & 0xFFFF)`
   **And** 1000 consecutive outputs match reference V8 implementation byte-for-byte

2. **Given** a timestamp in milliseconds (Unix epoch)
   **When** the PRNG is seeded from timestamp
   **Then** the seed derivation matches Chrome V8's seeding algorithm for the 2011-2015 era
   **And** the same timestamp always produces identical PRNG sequences

3. **Given** the MWC1616 implementation
   **When** compiled in release mode
   **Then** all arithmetic uses wrapping u32 operations (no overflow panics)
   **And** no floating-point operations are used (Integer Isolation Law)

## Tasks / Subtasks

- [x] Task 1: Validate existing MWC1616 implementation (AC: #1)
  - [x] 1.1 Review `engines/v8.rs` V8Reference::next_state() for formula correctness
  - [x] 1.2 Review `prng/chrome_v8.rs` ChromeV8Prng::generate_bytes() for consistency
  - [x] 1.3 Create 1000-output test vector from V8 3.14.5.9 source reference
  - [x] 1.4 Add test case asserting 1000 consecutive outputs match reference

- [x] Task 2: Validate timestamp seeding algorithm (AC: #2)
  - [x] 2.1 Research V8 3.14.5.9 seeding behavior (src/math.cc)
  - [x] 2.2 Verify generate_seed() in chrome_v8.rs matches V8 era behavior
  - [x] 2.3 Add deterministic test with known timestamp → expected s1/s2 state
  - [x] 2.4 Ensure identical sequences from identical timestamps (already covered by existing test)

- [x] Task 3: Enforce Integer Isolation Law (AC: #3)
  - [x] 3.1 Audit `engines/v8.rs` for any f32/f64 usage (verify none exists)
  - [x] 3.2 Audit `prng/chrome_v8.rs` for any floating-point operations
  - [x] 3.3 Add `#[deny(clippy::float_arithmetic)]` lint to scanner module
  - [x] 3.4 Verify all arithmetic uses `.wrapping_*` methods
  - [x] 3.5 Run `cargo clippy --release` to confirm no float warnings

- [x] Task 4: Consolidate duplicate implementations (AC: #1, #2)
  - [x] 4.1 Analyze overlap between `engines/v8.rs` and `prng/chrome_v8.rs`
  - [x] 4.2 Determine canonical implementation (V8Reference is Golden Reference)
  - [x] 4.3 Refactor `prng/chrome_v8.rs` to delegate to V8Reference::next_state()
  - [x] 4.4 Update all callers to use unified interface (ChromeV8Prng now uses V8Reference)

- [x] Task 5: Add Tier 4 verification test (AC: #1)
  - [x] 5.1 Add test vector to `tests/fixtures/randstorm_vectors.json`
  - [x] 5.2 Create integration test in `tests/randstorm_integration.rs`
  - [x] 5.3 Run full test suite: `cargo test` (all MWC1616-related tests pass)

## Dev Notes

### Algorithm Reference

The MWC1616 algorithm from Chrome V8 3.14.5.9:

```c
// From v8/src/math.cc (2011-2015 era)
static unsigned int state0, state1;

double V8Random() {
  state0 = 18000 * (state0 & 0xFFFF) + (state0 >> 16);
  state1 = 30903 * (state1 & 0xFFFF) + (state1 >> 16);
  return ((state0 << 16) + state1) / 4294967296.0;
}
```

**Critical Note**: The original V8 returns a `double`, but we ONLY need the integer computation:
- `result_u32 = (s1 << 16) + (s2 & 0xFFFF)` - integer only, no division
- Integer Isolation Law: NEVER use the float division in Rust implementation

### Architecture Constraints

From `project-context.md` and `architecture.md`:

| Constraint | Requirement | Source |
|:-----------|:------------|:-------|
| Integer Isolation Law | NO floats in scanner kernels. Use u32/u64 with explicit wrapping. | architecture.md:143 |
| Dual-Execution Cross-Check | GPU hits verified by CPU Golden Reference | architecture.md:144 |
| Bit-Perfect CI Lock | 100% parity on Tier 4 vectors | architecture.md:145 |
| Endianness Standard | All shared structs `#[repr(C)]` with u32 fields | architecture.md:146 |

### Existing Implementation Locations

| File | Purpose | Status |
|:-----|:--------|:-------|
| `crates/temporal-planetarium-lib/src/scans/randstorm/engines/v8.rs` | V8Reference::next_state() - Golden Reference | Implemented |
| `crates/temporal-planetarium-lib/src/scans/randstorm/prng/chrome_v8.rs` | ChromeV8Prng (PrngEngine trait impl) | Implemented |
| `crates/temporal-planetarium-lib/src/scans/randstorm/core_types.rs` | ChromeV8State struct (#[repr(C)]) | Implemented |

### Key Constants

```rust
const MWC_MULTIPLIER_S1: u32 = 18000;
const MWC_MULTIPLIER_S2: u32 = 30903;
```

These constants come from George Marsaglia's MWC1616 paper. Chrome V8 used this specific variant.

### Project Structure Notes

- **Kernel centralization**: Any OpenCL logic goes in `cl/` directory (not applicable to this CPU-only story)
- **Module pattern**: Use `cpu::` and `gpu::` module separation for hardware parity
- **Testing location**: Integration tests in `tests/randstorm_integration.rs`
- **Naming**: `PascalCase` for structs, `snake_case` for functions

### References

- [Source: crates/temporal-planetarium-lib/src/scans/randstorm/engines/v8.rs] - V8Reference implementation
- [Source: crates/temporal-planetarium-lib/src/scans/randstorm/prng/chrome_v8.rs] - ChromeV8Prng PrngEngine impl
- [Source: crates/temporal-planetarium-lib/src/scans/randstorm/core_types.rs] - ChromeV8State struct
- [Source: crates/temporal-planetarium-lib/src/scans/randstorm/test_vectors.rs] - Known test vectors
- [Source: project-context.md#Critical-Implementation-Rules] - Zero-Tolerance Accuracy Laws
- [Source: architecture.md#Zero-Tolerance-Accuracy-Laws] - Integer Isolation Law, Dual-Execution Cross-Check
- [External: V8 source v3.14.5.9] - https://github.com/v8/v8/blob/3.14.5.9/src/math.cc

## Dev Agent Record

### Agent Model Used

Claude Opus 4.5 (claude-opus-4-5-20251101)

### Debug Log References

- All tests pass: `cargo test --lib mwc1616`, `cargo test --lib chrome_v8`, `cargo test --lib v8_reference`, `cargo test --test randstorm_integration`

### Completion Notes List

- Validated MWC1616 formula correctness against V8 3.14.5.9 source
- Created canonical 1000-output test vector with SHA256 hash: `466326718f1550191ee60476fb98299c1ad45cbfcdb61d621f83e0a6527323f2`
- Verified timestamp seeding: s1 = low 32 bits, s2 = high 32 bits
- Added `#![deny(clippy::float_arithmetic)]` to both v8.rs and chrome_v8.rs modules
- Refactored ChromeV8Prng to delegate to V8Reference::next_state() (single source of truth)
- All arithmetic uses `.wrapping_mul()` and `.wrapping_add()` for Integer Isolation Law compliance
- Created `tests/fixtures/randstorm_vectors.json` with Tier 4 verification vectors
- Added integration test `test_tier4_mwc1616_1000_output_verification` to verify bit-perfect implementation

### File List

- `crates/temporal-planetarium-lib/src/scans/randstorm/engines/v8.rs` (modified: added tests, lint denies)
- `crates/temporal-planetarium-lib/src/scans/randstorm/prng/chrome_v8.rs` (modified: refactored to use V8Reference, added lint denies)
- `crates/temporal-planetarium-lib/Cargo.toml` (modified: added randstorm_integration test target)
- `tests/randstorm_integration.rs` (modified: added Tier 4 verification test)
- `tests/fixtures/randstorm_vectors.json` (new: Tier 4 verification vectors)

### Change Log

- 2025-12-25: Story implementation complete - all 5 tasks completed, all ACs satisfied

