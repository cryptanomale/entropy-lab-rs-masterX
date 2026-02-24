use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use temporal_planetarium_lib::scans;
use tracing::info;

mod commands;

#[derive(Parser)]
#[command(name = "entropy-lab")]
#[command(about = "Research tool for wallet vulnerabilities", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch GUI interface for interactive scanning
    #[cfg(feature = "gui")]
    Gui,
    /// Reproduce Cake Wallet 2024 Vulnerability
    CakeWallet {
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Scan only the 8,717 confirmed vulnerable Cake Wallet seeds
    CakeWalletTargeted,
    /// Find seed from Cake Wallet address (GPU) - checks prefix "100" and 40 addresses
    CakeWalletCrack {
        #[arg(long)]
        target: String,
    },
    /// Reverse-engineer Cake Wallet seeds using Dart PRNG (time-based)
    CakeWalletDartPrng,
    /// Reproduce Trust Wallet 2023 Vulnerability
    TrustWallet {
        #[arg(long)]
        target: Option<String>,
    },
    /// Reproduce Mobile Sensor Entropy Vulnerability
    MobileSensor {
        #[arg(long)]
        target: Option<String>,
    },
    /// Reproduce Libbitcoin "Milk Sad" Vulnerability
    MilkSad {
        #[arg(long)]
        target: Option<String>,
        /// File with Bitcoin addresses to scan (one per line, # for comments)
        #[arg(long)]
        target_file: Option<std::path::PathBuf>,
        #[arg(long)]
        start_timestamp: Option<u32>,
        #[arg(long)]
        end_timestamp: Option<u32>,
        #[arg(long, default_value = "false")]
        multipath: bool,
        /// Entropy size in bits: 128 (12 words), 192 (18 words), 256 (24 words, Update #13)
        #[arg(long, default_value = "256", value_parser = clap::value_parser!(u32).range(128..=256))]
        entropy_bits: u32,
        #[arg(long)]
        rpc_url: Option<String>,
        #[arg(long)]
        rpc_user: Option<String>,
        #[arg(long)]
        rpc_pass: Option<String>,
        #[arg(long)]
        db_path: Option<std::path::PathBuf>,
    },
    /// Reproduce Malicious Browser Extension Logic
    MaliciousExtension,
    /// Verify CSV against funded addresses
    VerifyCsv {
        #[arg(long)]
        input: String,
        #[arg(long)]
        addresses: String,
    },
    /// Scan Cake Wallet vulnerability with RPC balance checking
    CakeWalletRpc {
        #[arg(long, default_value = "http://127.0.0.1:8332")]
        rpc_url: String,
        #[arg(long)]
        rpc_user: String,
        #[arg(long)]
        rpc_pass: String,
    },
    /// Scan Android SecureRandom vulnerability (duplicate R values)
    AndroidSecureRandom {
        #[arg(long, default_value = "http://127.0.0.1:8332")]
        rpc_url: String,
        #[arg(long)]
        rpc_user: String,
        #[arg(long)]
        rpc_pass: String,
        #[arg(long, default_value = "302000")]
        start_block: u64,
        #[arg(long, default_value = "330000")]
        end_block: u64,
    },
    /// Reproduce Profanity Vanity Address Vulnerability
    Profanity {
        #[arg(long)]
        target: Option<String>,
    },
    /// Build a Bloom Filter from a list of addresses
    BuildBloom {
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        #[arg(long, default_value = "1000000000")]
        expected_items: usize,
        #[arg(long, default_value = "0.0001")]
        fp_rate: f64,
    },
    /// Scan for bip3x (PCG-XSH-RR) vulnerability
    Bip3x,
    /// Scan for EC-New (Direct PRNG) vulnerability
    EcNew {
        #[arg(long)]
        target: String,
        #[arg(long)]
        start: Option<u32>,
        #[arg(long)]
        end: Option<u32>,
    },
    /// Scan for Trust Wallet iOS LCG (minstd_rand0) vulnerability
    ///
    /// Provide exactly one of --target or --targets.
    ///
    /// Examples:
    ///   entropy-lab trust-wallet-lcg --target 1BpEi6DfDAUFd153wiGrvkiKW1iHBa4Lnn
    ///   entropy-lab trust-wallet-lcg --targets /path/to/addresses.csv
    ///   entropy-lab trust-wallet-lcg --targets wallets.csv --start 1498780800 --end 1685836800
    TrustWalletLcg {
        /// Single Bitcoin address to scan for (P2PKH 1... or P2WPKH bc1q...).
        /// Mutually exclusive with --targets.
        #[arg(long, conflicts_with = "targets")]
        target: Option<String>,

        /// CSV / plain-text file containing one Bitcoin address per line.
        /// Lines starting with '#' are treated as comments.
        /// The first comma/tab/space-delimited column is used as the address;
        /// extra columns (labels, amounts, etc.) are ignored.
        /// Mutually exclusive with --target.
        #[arg(long, conflicts_with = "target")]
        targets: Option<std::path::PathBuf>,

        /// Unix timestamp to start scanning from (default: 2011-01-01 = 1293840000).
        #[arg(long)]
        start: Option<u32>,

        /// Unix timestamp to stop scanning at (default: 2025-01-01 = 1735689600).
        #[arg(long)]
        end: Option<u32>,
    },
    /// Randstorm vulnerability scanner
    RandstormScan {
        #[arg(long, required = true)]
        target_addresses: std::path::PathBuf,
        #[arg(long)]
        start_ms: Option<u64>,
        #[arg(long)]
        end_ms: Option<u64>,
        #[arg(long, default_value = "100")]
        interval_ms: u64,
        #[arg(long, default_value = "1")]
        phase: u8,
        #[arg(long, default_value = "standard")]
        mode: String,
        #[arg(long, conflicts_with = "cpu")]
        gpu: bool,
        #[arg(long, conflicts_with = "gpu")]
        cpu: bool,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long)]
        output: Option<std::path::PathBuf>,
        #[arg(long, default_value = "v8")]
        randstorm_engine: String,
        #[arg(long)]
        randstorm_seed_override: Option<u64>,
        #[arg(long)]
        randstorm_seed_bruteforce_bits: Option<u8>,
        #[arg(long)]
        randstorm_include_uncompressed: bool,
        #[arg(long)]
        estimate: bool,
        #[arg(long)]
        z3_solve: Option<String>,
        #[arg(long, default_value = "legacy")]
        path_coverage: String,
        #[arg(long)]
        db: Option<std::path::PathBuf>,
        #[arg(long)]
        class: Option<String>,
        /// CSV with fingerprints for GPU sweep (screen_width,screen_height,color_depth,timezone_offset)
        #[arg(long)]
        fingerprints_csv: Option<std::path::PathBuf>,
    },
    /// Import targets from CSV into the database
    DbImport {
        #[arg(long)]
        csv: std::path::PathBuf,
        #[arg(long)]
        class: String,
        #[arg(long, default_value = "targets.db")]
        db: std::path::PathBuf,
    },
    /// Query targets from the database
    DbQuery {
        #[arg(long)]
        class: String,
        #[arg(long, default_value = "10")]
        limit: usize,
        #[arg(long, default_value = "targets.db")]
        db: std::path::PathBuf,
    },
    /// Recover private key from ECDSA nonce reuse
    NonceReuseRecovery {
        #[arg(long)]
        z1: String,
        #[arg(long)]
        z2: String,
        #[arg(long)]
        r: String,
        #[arg(long)]
        s1: String,
        #[arg(long)]
        s2: String,
        #[arg(long)]
        output: std::path::PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Validate bit-parity between CPU Golden Reference and GPU backends
    RandstormValidate {
        #[arg(long, default_value = "wgpu")]
        backend: String,
        #[arg(long, default_value = "1000")]
        count: u64,
        #[arg(long, default_value = "v8")]
        engine: String,
    },
    /// Scan blockchain for ECDSA nonce reuse vulnerabilities
    NonceReuseCrawler {
        #[arg(long, default_value = "http://127.0.0.1:8332")]
        rpc_url: String,
        #[arg(long)]
        rpc_user: String,
        #[arg(long)]
        rpc_pass: String,
        #[arg(long, default_value = "nonce_reuse.db")]
        db: std::path::PathBuf,
        #[arg(long)]
        start_block: Option<u64>,
        #[arg(long)]
        end_block: Option<u64>,
        #[arg(long)]
        last_n_blocks: Option<u64>,
        #[arg(long)]
        resume: bool,
        #[arg(long, env = "NONCE_CRAWLER_PASSPHRASE")]
        passphrase: Option<String>,
        #[arg(long, default_value = "50")]
        rate_limit_ms: u64,
    },
    /// List recovered private keys from nonce reuse database
    ListRecoveredKeys {
        #[arg(long, default_value = "nonce_reuse.db")]
        db: std::path::PathBuf,
        #[arg(long, env = "NONCE_CRAWLER_PASSPHRASE")]
        passphrase: Option<String>,
        #[arg(long, default_value = "table")]
        format: String,
        #[arg(long)]
        show_keys: bool,
    },
    /// Import brainwallet dictionary and generate addresses
    BrainwalletImport {
        #[arg(long)]
        wordlist: std::path::PathBuf,
        #[arg(long, default_value = "targets.db")]
        db_path: std::path::PathBuf,
        #[arg(long, default_value = "sha256-1x")]
        hash_type: String,
        #[arg(long, default_value = "p2pkh-compressed")]
        address_type: String,
        #[arg(long)]
        dry_run: bool,
    },
}

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8332";

fn get_rpc_credentials(
    url: String,
    user: String,
    pass: String,
) -> Result<(String, String, String)> {
    let final_url = if url == DEFAULT_RPC_URL {
        std::env::var("RPC_URL").unwrap_or(url)
    } else {
        url
    };

    let final_user = if user.is_empty() {
        std::env::var("RPC_USER").map_err(|_| {
            anyhow::anyhow!(
                "RPC_USER must be provided via --rpc-user flag or RPC_USER environment variable"
            )
        })?
    } else {
        user
    };

    let final_pass = if pass.is_empty() {
        std::env::var("RPC_PASS").map_err(|_| {
            anyhow::anyhow!(
                "RPC_PASS must be provided via --rpc-user flag or RPCPASS environment variable"
            )
        })?
    } else {
        pass
    };

    Ok((final_url, final_user, final_pass))
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        #[cfg(feature = "gui")]
        Commands::Gui => {
            info!("Launching GUI interface...");
            temporal_planetarium_lib::gui::run_gui()?;
        }
        Commands::CakeWallet { limit } => {
            info!("Running Cake Wallet Vulnerability Reproduction...");
            scans::cake_wallet::run_standard(limit)?;
        }
        Commands::CakeWalletTargeted => {
            info!("Running Cake Wallet TARGETED Scan (8,717 confirmed vulnerable seeds)...");
            scans::cake_wallet::run_targeted()?;
        }
        Commands::CakeWalletCrack { target } => {
            info!("Running Cake Wallet GPU Cracker (timestamp mode)...");
            scans::cake_wallet::run_crack_timestamp(&target)?;
        }
        Commands::CakeWalletDartPrng => {
            info!("Running Cake Wallet Dart PRNG Scanner (time-based reconstruction)...");
            scans::cake_wallet::run_prng()?;
        }
        Commands::TrustWallet { target } => {
            info!("Running Trust Wallet Vulnerability Reproduction...");
            scans::trust_wallet::run_standard(target)?;
        }
        Commands::MobileSensor { target } => {
            info!("Running Mobile Sensor Entropy Reproduction...");
            scans::mobile_sensor::run(target)?;
        }
        Commands::MilkSad {
            target,
            target_file,
            start_timestamp,
            end_timestamp,
            multipath,
            entropy_bits,
            rpc_url,
            rpc_user,
            rpc_pass,
            db_path,
        } => {
            info!("Running Libbitcoin 'Milk Sad' Vulnerability Reproduction...");

            let entropy_size = match entropy_bits {
                192 => scans::milk_sad::EntropySize::Bits192,
                256 => scans::milk_sad::EntropySize::Bits256,
                _   => scans::milk_sad::EntropySize::Bits128,
            };

            let rpc_config =
                if let (Some(url), Some(user), Some(pass)) = (rpc_url, rpc_user, rpc_pass) {
                    Some(get_rpc_credentials(url, user, pass)?)
                } else {
                    None
                };

            scans::milk_sad::run_scan(
                target,
                target_file,
                start_timestamp,
                end_timestamp,
                multipath,
                entropy_size,
                rpc_config,
                db_path,
            )?;
        }
        Commands::MaliciousExtension => {
            info!("Running Malicious Extension Reproduction...");
            scans::malicious_extension::run()?;
        }
        Commands::Profanity { target } => {
            info!("Running Profanity Vanity Address Vulnerability Reproduction...");
            scans::profanity::run(target)?;
        }
        Commands::VerifyCsv { input, addresses } => {
            info!("Running CSV Verification...");
            scans::verify_csv::run(&input, &addresses)?;
        }
        Commands::CakeWalletRpc {
            rpc_url,
            rpc_user,
            rpc_pass,
        } => {
            info!("Running Cake Wallet RPC Scanner...");
            let (url, user, pass) = get_rpc_credentials(rpc_url, rpc_user, rpc_pass)?;
            scans::cake_wallet::run_rpc(&url, &user, &pass)?;
        }
        Commands::AndroidSecureRandom {
            rpc_url,
            rpc_user,
            rpc_pass,
            start_block,
            end_block,
        } => {
            info!("Running Android SecureRandom Scanner...");
            let (url, user, pass) = get_rpc_credentials(rpc_url, rpc_user, rpc_pass)?;
            scans::android_securerandom::run(&url, &user, &pass, start_block, end_block)?;
        }
        Commands::BuildBloom {
            input,
            output,
            expected_items,
            fp_rate,
        } => {
            info!("Building Bloom Filter...");
            temporal_planetarium_lib::utils::bloom_filter::build_from_file(
                &input,
                &output,
                expected_items,
                fp_rate,
            )?;
        }
        Commands::Bip3x => {
            scans::bip3x::run()?;
        }
        Commands::EcNew { target, start, end } => {
            scans::ec_new::run(&target, start, end)?;
        }
        Commands::TrustWalletLcg { target, targets, start, end } => {
            let start_ts = start.unwrap_or(1_293_840_000); // 2011-01-01
            let end_ts   = end.unwrap_or(1_735_689_600);   // 2025-01-01

            match (target, targets) {
                (Some(addr), None) => {
                    scans::trust_wallet::run_lcg(&addr, start_ts, end_ts)?;
                }
                (None, Some(path)) => {
                    scans::trust_wallet::run_lcg_multi_file(&path, start_ts, end_ts)?;
                }
                (None, None) => {
                    anyhow::bail!(
                        "Provide either --target <address> or --targets <file.csv>"
                    );
                }
                (Some(_), Some(_)) => unreachable!("clap conflicts_with prevents this"),
            }
        }
        Commands::RandstormScan {
            target_addresses,
            start_ms,
            end_ms,
            interval_ms,
            phase,
            mode,
            gpu,
            cpu,
            backend,
            output,
            randstorm_engine,
            randstorm_seed_override,
            randstorm_seed_bruteforce_bits,
            randstorm_include_uncompressed,
            estimate,
            z3_solve,
            path_coverage,
            db,
            class,
            fingerprints_csv,
        } => {
            scans::randstorm::cli::run_scan(
                &target_addresses,
                start_ms,
                end_ms,
                interval_ms,
                phase,
                &mode,
                gpu,
                cpu,
                output.as_deref(),
                backend.as_deref(),
                &randstorm_engine,
                randstorm_seed_override,
                randstorm_seed_bruteforce_bits,
                randstorm_include_uncompressed,
                estimate,
                z3_solve.as_deref(),
                &path_coverage,
                db.as_deref(),
                class.as_deref(),
                fingerprints_csv.as_deref(),
            )?;
        }
        Commands::RandstormValidate { backend, count, engine } => {
            scans::randstorm::cli::run_validate_parity(&backend, count, &engine)?;
        }
        Commands::DbImport { csv, class, db } => {
            info!("Importing targets from {:?} into {} class...", csv, class);
            let target_db = temporal_planetarium_lib::utils::db::TargetDatabase::new(db)?;
            let file = std::fs::File::open(csv)?;
            let mut reader = csv::ReaderBuilder::new()
                .has_headers(false)
                .from_reader(file);
            let mut count = 0;
            for result in reader.records() {
                let record = result?;
                let address = record.get(0).context("Missing address or passphrase in CSV row")?.to_string();

                if class == "brainwallet" {
                    target_db.add_intelligence("passphrase", &address, None, Some("brainwallet"))?;

                    if let Ok(derived_targets) = temporal_planetarium_lib::scans::randstorm::heuristics::generate_heuristic_targets(&address) {
                        for (derived_addr, variation) in derived_targets {
                            let target = temporal_planetarium_lib::utils::db::Target {
                                address: derived_addr,
                                vuln_class: class.clone(),
                                first_seen_timestamp: None,
                                metadata_json: Some(format!("{{\"passphrase\": \"{}\", \"variation_of\": \"{}\"}}", variation, address)),
                                status: "pending".to_string(),
                                ..Default::default()
                            };
                            target_db.upsert_target(&target)?;
                        }
                    }
                } else {
                    let target = temporal_planetarium_lib::utils::db::Target {
                        address,
                        vuln_class: class.clone(),
                        first_seen_timestamp: None,
                        metadata_json: None,
                        status: "pending".to_string(),
                        ..Default::default()
                    };
                    target_db.upsert_target(&target)?;
                }
                count += 1;
            }
            info!("Successfully imported {} targets.", count);
        }
        Commands::DbQuery { class, limit, db } => {
            info!("Querying top {} targets for {}...", limit, class);
            let target_db = temporal_planetarium_lib::utils::db::TargetDatabase::new(db)?;
            let results = target_db.query_by_class(&class, limit)?;
            for t in results {
                println!("{}", t.address);
            }
        }
        Commands::NonceReuseRecovery { z1, z2, r, s1, s2, output, passphrase } => {
            use temporal_planetarium_lib::utils::encryption::{encrypt_private_key, DEFAULT_ENCRYPTION_PASSPHRASE};

            info!("Running ECDSA Nonce Reuse Recovery...");
            let z1_bytes = hex::decode(z1)?.try_into().map_err(|_| anyhow::anyhow!("z1 must be 32 bytes"))?;
            let z2_bytes = hex::decode(z2)?.try_into().map_err(|_| anyhow::anyhow!("z2 must be 32 bytes"))?;
            let r_bytes  = hex::decode(r)?.try_into().map_err(|_| anyhow::anyhow!("r must be 32 bytes"))?;
            let s1_bytes = hex::decode(s1)?.try_into().map_err(|_| anyhow::anyhow!("s1 must be 32 bytes"))?;
            let s2_bytes = hex::decode(s2)?.try_into().map_err(|_| anyhow::anyhow!("s2 must be 32 bytes"))?;

            let pass = passphrase
                .or_else(|| std::env::var("NONCE_CRAWLER_PASSPHRASE").ok())
                .unwrap_or_else(|| {
                    tracing::warn!("\u{26a0}\u{fe0f}  Using default encryption passphrase. Set --passphrase or NONCE_CRAWLER_PASSPHRASE for production use.");
                    DEFAULT_ENCRYPTION_PASSPHRASE.to_string()
                });

            match temporal_planetarium_lib::scans::randstorm::forensics::recover_privkey_from_nonce_reuse(
                &z1_bytes, &z2_bytes, &r_bytes, &s1_bytes, &s2_bytes
            ) {
                Ok(sk) => {
                    info!("\u{2705} SUCCESS! Private key recovered!");

                    let wif = bitcoin::PrivateKey::new(sk, bitcoin::Network::Bitcoin).to_wif();
                    let encrypted = encrypt_private_key(&wif, &pass)?;

                    let secp = bitcoin::secp256k1::Secp256k1::new();
                    let pubkey = sk.public_key(&secp);
                    let address = bitcoin::Address::p2pkh(
                        bitcoin::CompressedPublicKey(pubkey),
                        bitcoin::Network::Bitcoin
                    );

                    let output_data = serde_json::json!({
                        "address": address.to_string(),
                        "network": "mainnet",
                        "encrypted_wif": hex::encode(&encrypted.ciphertext),
                        "nonce": hex::encode(&encrypted.nonce),
                        "salt": hex::encode(&encrypted.salt),
                        "encryption": "AES-256-GCM",
                        "kdf": "PBKDF2-HMAC-SHA256",
                        "kdf_iterations": 100000,
                        "recovered_from": "nonce_reuse",
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                        "warning": "PRIVATE KEY - Handle with extreme care."
                    });

                    std::fs::write(&output, serde_json::to_string_pretty(&output_data)?)?;
                    drop(wif);

                    println!("\u{1f510} Private key recovered and encrypted!");
                    println!("\u{1f4cd} Address: {}", address);
                    println!("\u{1f4be} Saved to: {}", output.display());
                    println!();
                    println!("\u{26a0}\u{fe0f}  SECURITY: Private key is encrypted with AES-256-GCM.");
                    println!("   To decrypt, use: entropy-lab list-recovered-keys --show-keys");
                }
                Err(e) => {
                    anyhow::bail!("Recovery failed: {}", e);
                }
            }
        }
        Commands::NonceReuseCrawler {
            rpc_url, rpc_user, rpc_pass, db,
            start_block, end_block, last_n_blocks,
            resume, passphrase, rate_limit_ms,
        } => {
            use temporal_planetarium_lib::utils::encryption::DEFAULT_ENCRYPTION_PASSPHRASE;
            let pass = passphrase.unwrap_or_else(|| DEFAULT_ENCRYPTION_PASSPHRASE.to_string());
            commands::nonce_crawler::run(
                rpc_url, rpc_user, rpc_pass, db,
                start_block, end_block, last_n_blocks,
                resume, pass, Some(rate_limit_ms),
            )?;
        }
        Commands::ListRecoveredKeys { db, passphrase, format, show_keys } => {
            use temporal_planetarium_lib::utils::encryption::DEFAULT_ENCRYPTION_PASSPHRASE;
            let pass = passphrase.unwrap_or_else(|| DEFAULT_ENCRYPTION_PASSPHRASE.to_string());
            let output_format = format.parse::<commands::list_keys::OutputFormat>()?;
            commands::list_keys::run(db, pass, output_format, show_keys)?;
        }
        Commands::BrainwalletImport { wordlist, db_path, hash_type, address_type, dry_run } => {
            commands::brainwallet_import::run(wordlist, db_path, hash_type, address_type, dry_run)?;
        }
    }

    Ok(())
}
