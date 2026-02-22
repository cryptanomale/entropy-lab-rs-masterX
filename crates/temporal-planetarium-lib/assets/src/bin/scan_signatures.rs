use anyhow::{Context, Result};
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::{Block, Transaction, OutPoint};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::collections::HashMap;
use std::path::PathBuf;
use temporal_planetarium_lib::scans::randstorm::forensics::recover_privkey_from_nonce_reuse;
use temporal_planetarium_lib::utils::db::{Target, TargetDatabase};
use tracing::{info, warn, error};

#[derive(Debug, Clone)]
struct SignaturePoint {
    z: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    txid: String,
    vin: usize,
    address: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    dotenv::dotenv().ok();

    let host = std::env::var("BITCOIN_RPC_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("BITCOIN_RPC_PORT").unwrap_or_else(|_| "8332".to_string());
    let rpc_user = std::env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "user".to_string());
    let rpc_pass = std::env::var("BITCOIN_RPC_PASS").unwrap_or_else(|_| "pass".to_string());
    
    let rpc_url = format!("http://{}:{}", host, port);
    let db_path = PathBuf::from("data/forensic_targets.db");

    println!("📡 On-Chain Signature Watcher starting...");
    println!("🔗 RPC: {}", rpc_url);

    let client = Client::new(&rpc_url, Auth::UserPass(rpc_user, rpc_pass))
        .context("Failed to connect to Bitcoin Core RPC")?;

    let mut db = TargetDatabase::new(db_path)?;
    
    // sig_map: r_value -> SignaturePoint
    let mut sig_map: HashMap<[u8; 32], SignaturePoint> = HashMap::new();

    let blockchain_info = client.get_blockchain_info()?;
    let current_height = blockchain_info.blocks;
    let start_height = current_height.saturating_sub(100); // Scan last 100 blocks by default

    println!("🔎 Scanning blocks {} to {}...", start_height, current_height);

    for height in start_height..=current_height {
        let block_hash = client.get_block_hash(height)?;
        let block: Block = client.get_by_id(&block_hash)?;

        for tx in &block.txdata {
            process_transaction(tx, &mut sig_map, &mut db)?;
        }

        if height % 10 == 0 {
            println!("📦 Height {}: Observed {} unique R-values", height, sig_map.len());
        }
    }

    println!("✨ Scan complete. Observed {} unique R-values.", sig_map.len());
    Ok(())
}

fn process_transaction(
    tx: &Transaction,
    sig_map: &mut HashMap<[u8; 32], SignaturePoint>,
    db: &mut TargetDatabase,
) -> Result<()> {
    for (vin, input) in tx.input.iter().enumerate() {
        // We only care about P2PKH inputs (standard signatures)
        // script_sig: <sig> <pubkey>
        let script = &input.script_sig;
        if script.is_empty() {
            continue;
        }

        // Try to parse as a signature
        // Note: This is a simplified parser. Real Bitcoin scripts are complex.
        // We look for 0x30 (DER prefix)
        let bytes = script.as_bytes();
        if let Some(der_start) = bytes.iter().position(|&b| b == 0x30) {
            // Found potential DER signature
            if bytes.len() > der_start + 2 {
                let sig_len = bytes[der_start + 1] as usize;
                if bytes.len() >= der_start + 2 + sig_len {
                    let der_sig = &bytes[der_start + 2 .. der_start + 2 + sig_len];
                    if let Ok((r, s)) = parse_der_r_s(der_sig) {
                        // Get message hash (z)
                        // In real life, we need the prevout script. 
                        // For a forensic sweep, we might just use a placeholder 
                        // OR fetch the prevout if we have a node.
                        // Fetching prevout for every input is EXTREMELY slow without txindex.
                        
                        // BUT: For nonce reuse recovery, we NEED the message hash.
                        // For now, let's just log the R-collision. 
                        // If R collides across two different TXs, we have a target.
                        
                        let entry = sig_map.entry(r).or_insert_with(|| SignaturePoint {
                            z: [0u8; 32], // Needs resolving from prevout
                            r,
                            s,
                            txid: tx.compute_txid().to_string(),
                            vin,
                            address: "unknown".to_string(),
                        });

                        if entry.txid != tx.compute_txid().to_string() || entry.vin != vin {
                            if entry.s != s {
                                warn!("🔥 NONCE REUSE DETECTED! R-value: {}", hex::encode(r));
                                warn!("   TX 1: {} vin: {}", entry.txid, entry.vin);
                                warn!("   TX 2: {} vin: {}", tx.compute_txid(), vin);
                                
                                // Recover key would happen here if we had z1, z2.
                                // We'll add it to DB as a "high priority forensics target".
                                db.upsert_target(&Target {
                                    address: format!("collision-{}", hex::encode(r)),
                                    vuln_class: "nonce_reuse".to_string(),
                                    first_seen_timestamp: None,
                                    metadata_json: Some(format!(r#"{{"r": "{}", "tx1": "{}", "tx2": "{}"}}"#, hex::encode(r), entry.txid, tx.compute_txid())),
                                    status: "pending".to_string(),
                                    ..Default::default()
                                })?;
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn parse_der_r_s(der: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    // Basic DER parser for signatures: 0x02 <len_r> <r> 0x02 <len_s> <s>
    if der.len() < 8 || der[0] != 0x02 {
        return Err(anyhow::anyhow!("Invalid DER"));
    }
    let r_len = der[1] as usize;
    let r_start = 2;
    if der.len() < r_start + r_len + 2 || der[r_start + r_len] != 0x02 {
        return Err(anyhow::anyhow!("Invalid DER R"));
    }
    let s_len = der[r_start + r_len + 1] as usize;
    let s_start = r_start + r_len + 2;
    if der.len() < s_start + s_len {
        return Err(anyhow::anyhow!("Invalid DER S"));
    }

    let r_bytes = &der[r_start .. r_start + r_len];
    let s_bytes = &der[s_start .. s_start + s_len];

    Ok((pad_32(r_bytes), pad_32(s_bytes)))
}

fn pad_32(bytes: &[u8]) -> [u8; 32] {
    let mut res = [0u8; 32];
    let len = bytes.len().min(32);
    let src_start = if bytes.len() > 32 { bytes.len() - 32 } else { 0 };
    let dest_start = 32 - len;
    res[dest_start..].copy_from_slice(&bytes[src_start..src_start+len]);
    res
}
