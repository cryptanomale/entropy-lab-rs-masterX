use anyhow::{Context, Result};
use bitcoin::{Block, Network, Address};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::collections::HashSet;
use std::path::PathBuf;
use temporal_planetarium_lib::utils::db::{Target, TargetDatabase};
use tracing::{info, warn};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    dotenv::dotenv().ok();

    let host = std::env::var("BITCOIN_RPC_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("BITCOIN_RPC_PORT").unwrap_or_else(|_| "8332".to_string());
    let rpc_user = std::env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "user".to_string());
    let rpc_pass = std::env::var("BITCOIN_RPC_PASS").unwrap_or_else(|_| "pass".to_string());
    
    let rpc_url = format!("http://{}:{}", host, port);
    let db_path = PathBuf::from("data/forensic_targets.db");

    println!("📅 Temporal Heuristic Harvester starting...");
    println!("🏛️ Target Window: 2011 - 2015");

    let client = Client::new(&rpc_url, Auth::UserPass(rpc_user, rpc_pass))
        .context("Failed to connect to Bitcoin Core RPC")?;

    let mut db = TargetDatabase::new(db_path)?;
    
    // We'll scan a few historically significant blocks if no range is provided
    // Block 200,000 is circa 2012. 
    let start_height = 100_000; // Early 2011
    let end_height = 350_000;   // Early 2015
    
    println!("🔎 Scanning block range {} to {}...", start_height, end_height);

    let mut batch = Vec::new();
    let mut seen_in_batch = HashSet::new();

    for height in (start_height..=end_height).step_by(100) { // Sampling every 100 blocks for efficiency
        let block_hash = client.get_block_hash(height)?;
        let block: Block = client.get_by_id(&block_hash)?;
        let timestamp = block.header.time;

        for tx in &block.txdata {
            for output in &tx.output {
                if let Ok(address) = Address::from_script(&output.script_pubkey, Network::Bitcoin) {
                    let addr_str = address.to_string();
                    if output.script_pubkey.is_p2pkh() && !seen_in_batch.contains(&addr_str) {
                        seen_in_batch.insert(addr_str.clone());
                        batch.push(Target {
                            address: addr_str,
                            vuln_class: "randstorm".to_string(),
                            first_seen_timestamp: Some(timestamp as i64),
                            metadata_json: Some(format!(r#"{{"height": {}}}"#, height)),
                            status: "pending".to_string(),
                            ..Default::default()
                        });
                    }
                }
            }
        }

        if batch.len() >= 500 {
            db.bulk_upsert_targets(&batch)?;
            println!("📦 Height {}: Ingested {} samples...", height, batch.len());
            batch.clear();
            seen_in_batch.clear();
        }
    }

    if !batch.is_empty() {
        db.bulk_upsert_targets(&batch)?;
    }

    println!("✨ Harvesting complete. Database: data/forensic_targets.db");
    Ok(())
}
