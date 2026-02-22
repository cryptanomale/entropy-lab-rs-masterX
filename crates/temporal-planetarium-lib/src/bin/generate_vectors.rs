//! Test Vector Generator
//! 
//! Generates 10,000+ test vectors for Randstorm scanning across all engines.
//! Output format matches tests/fixtures/shared_test_vectors.json.

use temporal_planetarium_lib::scans::randstorm::prng::MathRandomEngine;
use temporal_planetarium_lib::scans::randstorm::prng::bitcoinjs_v013::BitcoinJsV013Prng;
use bitcoin::{PrivateKey, Network, Address};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;

#[derive(Serialize, Deserialize, Debug)]
struct TestVector {
    vulnerability: String,
    engine: String,
    timestamp_ms: u64,
    seed: Option<u64>,
    expected_address: String,
    expected_privkey: Option<String>,
    expected_privkey_hex: String,
}

fn main() -> anyhow::Result<()> {
    let mut vectors = Vec::with_capacity(10000);
    
    // Engine mapping for output
    let engines = [
        (MathRandomEngine::V8Mwc1616, "v8"),
        (MathRandomEngine::SpiderMonkeyLcg, "java"),
        (MathRandomEngine::IeChakraLcg, "ie"),
        (MathRandomEngine::SafariWindowsCrt, "safari-win"),
    ];

    let start_ts: u64 = 1306886400000; // 2011-06-01
    let interval: u64 = 3600_000 * 24; // 1 day interval for broad coverage
    
    println!("🚀 Generating 10,000 test vectors...");

    for i in 0..2500 {
        let ts = start_ts + (i as u64 * interval);
        
        for (engine, engine_name) in &engines {
            let key_bytes = BitcoinJsV013Prng::generate_privkey_bytes(ts, *engine, None);
            
            if let Ok(privkey) = PrivateKey::from_slice(&key_bytes, Network::Bitcoin) {
                let pubkey = privkey.public_key(&bitcoin::secp256k1::Secp256k1::new());
                let address = Address::p2pkh(pubkey, Network::Bitcoin);
                
                vectors.push(TestVector {
                    vulnerability: "randstorm".to_string(),
                    engine: engine_name.to_string(),
                    timestamp_ms: ts,
                    seed: None,
                    expected_address: address.to_string(),
                    expected_privkey: Some(privkey.to_string()),
                    expected_privkey_hex: hex::encode(key_bytes),
                });
            }
        }
    }

    let json = serde_json::to_string_pretty(&vectors)?;
    let mut file = File::create("tests/fixtures/comprehensive_test_vectors.json")?;
    file.write_all(json.as_bytes())?;

    println!("✅ Successfully generated {} vectors to tests/fixtures/comprehensive_test_vectors.json", vectors.len());
    Ok(())
}
