use anyhow::{Context, Result};
use bip39::{Mnemonic, Language};
use sha2::Digest;
use csv::Reader;
use serde::Deserialize;
use std::path::PathBuf;
use temporal_planetarium_lib::scans::randstorm::derivation::derive_p2pkh_address_from_bytes;
use temporal_planetarium_lib::utils::db::{Target, TargetDatabase};

#[derive(Debug, Deserialize)]
struct MilkSadRecord {
    timestamp: u64,
    seed: String,
    mnemonic: String,
}

fn main() -> Result<()> {
    let csv_path = "/Users/moe/temporal-planetarium/trust_wallet_ms_sample.csv";
    let db_path = PathBuf::from("data/forensic_targets.db");

    println!("🚀 Starting Forensic Ingestion Loop...");
    println!("📂 Source: {}", csv_path);
    println!("🗄️  Target DB: {:?}", db_path);

    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut db = TargetDatabase::new(db_path)?;
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(csv_path)
        .context("Failed to open CSV")?;
    
    let mut targets = Vec::new();
    let mut count = 0;

    for result in reader.records() {
        let record = result?;
        
        let timestamp_str = record.get(0).unwrap_or("0");
        let seed_str = record.get(1).unwrap_or("");
        let mnemonic_phrase = record.get(2).unwrap_or("");

        let timestamp: i64 = timestamp_str.parse().unwrap_or(0);
        
        // 1. Recover Mnemonic
        if let Ok(mnemonic) = Mnemonic::parse(mnemonic_phrase) {
            // Seed in this CSV is often a 32-bit decimal integer
            let seed_val: u64 = seed_str.parse().unwrap_or(0);
            
            // Try to derive address
            // Scenario A: Seed is actually the entropy
            let entropy = mnemonic.to_entropy();
            
            // Scenario B: Derive from the 32-bit seed (simulating the weak PRNG)
            // For target acquisition, we'll try two common layouts:
            // 1. Using first 32 bytes of entropy as privkey
            // 2. Using seed value as a primitive "private key" (padding with zeros)
            
            let mut privkey_bytes = [0u8; 32];
            if entropy.len() >= 16 {
                // BIP39 standard: entropy is 16-32 bytes. 
                // We'll hash it to get 32 bytes for a privkey if needed, 
                // but usually Milk Sad wallets used the seed to generate entropy.
                
                // For this acquisition phase, let's just use the First 32 bytes of the SEED if possible
                // OR just the entropy itself.
                let mut hasher = sha2::Sha256::new();
                sha2::Digest::update(&mut hasher, &entropy);
                let hashed_entropy = sha2::Digest::finalize(hasher);
                privkey_bytes.copy_from_slice(&hashed_entropy);
            } else {
                // Fallback to seed value
                let bytes = seed_val.to_be_bytes();
                privkey_bytes[24..32].copy_from_slice(&bytes);
            }

            if let Ok(address) = derive_p2pkh_address_from_bytes(&privkey_bytes) {
                targets.push(Target {
                    address,
                    vuln_class: "milk_sad".to_string(),
                    first_seen_timestamp: Some(timestamp),
                    metadata_json: Some(format!(r#"{{"mnemonic": "{}", "seed": "{}"}}"#, mnemonic_phrase, seed_str)),
                    status: "pending".to_string(),
                    ..Default::default()
                });
            }
        }

        count += 1;
        if targets.len() >= 1000 {
            db.bulk_upsert_targets(&targets)?;
            println!("✅ Ingested {} targets...", count);
            targets.clear();
        }
    }

    if !targets.is_empty() {
        db.bulk_upsert_targets(&targets)?;
    }

    println!("✨ Ingestion Complete. Total Processed: {}", count);
    Ok(())
}
