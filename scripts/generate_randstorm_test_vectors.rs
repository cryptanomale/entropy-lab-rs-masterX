#!/usr/bin/env rust-script
//! Generate test vectors for Randstorm vulnerability validation
//! 
//! This creates 1,000 Bitcoin addresses using the vulnerable BitcoinJS
//! entropy generation pattern (weak Math.random seeding from 2011-2015 era)
//! 
//! Usage: cargo run --bin generate_randstorm_test_vectors

use std::fs::File;
use std::io::Write;
use bitcoin::{
    secp256k1::{Secp256k1, SecretKey},
    PublicKey, Address, Network,
};
use sha2::{Sha256, Digest};

/// Simulates the vulnerable BitcoinJS SecureRandom() entropy collection
/// This replicates the flaw where Math.random() (48-bit LCG) was used
/// instead of a proper CSPRNG
struct VulnerablePRNG {
    seed: u64,
    timestamp_ms: u64,
}

impl VulnerablePRNG {
    /// Create PRNG with fixed timestamp (simulating wallet creation time)
    fn new(timestamp_ms: u64, sequence: u32) -> Self {
        // Simulate the weak entropy collection from BitcoinJS 0.1.3
        // Uses timestamp + Math.random() equivalent (48-bit LCG)
        let seed = timestamp_ms ^ (sequence as u64);
        Self {
            seed,
            timestamp_ms,
        }
    }

    /// Simulate JavaScript Math.random() - 48-bit Linear Congruential Generator
    /// This is the source of the vulnerability
    fn next_random(&mut self) -> f64 {
        // Parameters from V8's Math.random() implementation (pre-2015)
        const MULTIPLIER: u64 = 25214903917;
        const INCREMENT: u64 = 11;
        const MODULUS: u64 = (1u64 << 48) - 1;

        self.seed = (self.seed.wrapping_mul(MULTIPLIER).wrapping_add(INCREMENT)) & MODULUS;
        (self.seed as f64) / (MODULUS as f64)
    }

    /// Generate 32 bytes of entropy using the vulnerable method
    /// This simulates the SecureRandom() pool collection
    fn generate_entropy(&mut self) -> [u8; 32] {
        let mut entropy = [0u8; 32];
        
        // First 8 bytes: timestamp
        entropy[0..8].copy_from_slice(&self.timestamp_ms.to_le_bytes());
        
        // Remaining 24 bytes: weak random values
        for i in 0..3 {
            let rand_val = (self.next_random() * 65536.0) as u64;
            entropy[8 + i*8..8 + (i+1)*8].copy_from_slice(&rand_val.to_le_bytes());
        }
        
        entropy
    }

    /// Derive private key from vulnerable entropy
    fn derive_private_key(&mut self) -> SecretKey {
        let entropy = self.generate_entropy();
        
        // Hash the weak entropy to create private key
        let mut hasher = Sha256::new();
        hasher.update(&entropy);
        let hash = hasher.finalize();
        
        SecretKey::from_slice(&hash)
            .expect("32 bytes should always be valid")
    }
}

/// Browser fingerprint for Randstorm attack
#[derive(Debug, Clone)]
struct BrowserFingerprint {
    timestamp_ms: u64,
    user_agent: String,
    screen_width: u16,
    screen_height: u16,
    timezone_offset: i16,
    language: String,
}

impl BrowserFingerprint {
    fn fingerprint_hash(&self) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(self.timestamp_ms.to_le_bytes());
        hasher.update(self.user_agent.as_bytes());
        hasher.update(self.screen_width.to_le_bytes());
        hasher.update(self.screen_height.to_le_bytes());
        hasher.update(self.timezone_offset.to_le_bytes());
        hasher.update(self.language.as_bytes());
        
        let hash = hasher.finalize();
        u64::from_le_bytes(hash[0..8].try_into().unwrap())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔬 Generating Randstorm Test Vectors");
    println!("═══════════════════════════════════════════════════════════");
    
    let secp = Secp256k1::new();
    let network = Network::Testnet;
    
    // Fixed timestamp: January 15, 2014, 10:30:00 UTC
    // This is within the vulnerable period (2011-2015)
    let base_timestamp_ms = 1389781800000u64;
    
    // Common browser fingerprints from 2014
    let fingerprints = vec![
        BrowserFingerprint {
            timestamp_ms: base_timestamp_ms,
            user_agent: "Mozilla/5.0 (Windows NT 6.1) Chrome/32.0.1700.76".to_string(),
            screen_width: 1920,
            screen_height: 1080,
            timezone_offset: -300, // EST
            language: "en-US".to_string(),
        },
        BrowserFingerprint {
            timestamp_ms: base_timestamp_ms + 1000,
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) Safari/537.73.11".to_string(),
            screen_width: 1440,
            screen_height: 900,
            timezone_offset: -480, // PST
            language: "en-US".to_string(),
        },
        BrowserFingerprint {
            timestamp_ms: base_timestamp_ms + 2000,
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) Firefox/26.0".to_string(),
            screen_width: 1366,
            screen_height: 768,
            timezone_offset: 0, // GMT
            language: "en-GB".to_string(),
        },
    ];
    
    let mut output_file = File::create("randstorm_test_vectors.csv")?;
    writeln!(output_file, "index,timestamp_ms,private_key_hex,wif,address,fingerprint_hash")?;
    
    let mut vulnerable_keys = Vec::new();
    
    println!("\n📊 Generating 1,000 test keys...\n");
    
    for i in 0..1000 {
        // Cycle through fingerprints and add time variation
        let fp_index = i % fingerprints.len();
        let mut fp = fingerprints[fp_index].clone();
        fp.timestamp_ms += (i / fingerprints.len()) as u64 * 100; // 100ms increments
        
        let fp_hash = fp.fingerprint_hash();
        
        // Generate vulnerable private key
        let mut prng = VulnerablePRNG::new(fp.timestamp_ms, i as u32);
        let secret_key = prng.derive_private_key();
        
        // Derive public key and address
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = Address::p2pkh(&public_key, network);
        
        // Get WIF format
        let private_key_wif = bitcoin::PrivateKey {
            compressed: true,
            network,
            inner: secret_key,
        }.to_wif();
        
        vulnerable_keys.push((
            i,
            fp.timestamp_ms,
            hex::encode(secret_key.secret_bytes()),
            private_key_wif.clone(),
            address.to_string(),
            fp_hash,
        ));
        
        writeln!(
            output_file,
            "{},{},{},{},{},{}",
            i,
            fp.timestamp_ms,
            hex::encode(secret_key.secret_bytes()),
            private_key_wif,
            address,
            fp_hash
        )?;
        
        if i % 100 == 0 {
            println!("  ✓ Generated {} keys...", i);
        }
    }
    
    println!("\n✅ Generated 1,000 vulnerable test keys");
    println!("📁 Output: randstorm_test_vectors.csv");
    
    // Print first 5 for verification
    println!("\n📋 Sample Keys (first 5):");
    println!("═══════════════════════════════════════════════════════════");
    for (idx, ts, _priv, wif, addr, fp) in vulnerable_keys.iter().take(5) {
        println!("\n[{}] Timestamp: {}", idx, ts);
        println!("    Address: {}", addr);
        println!("    WIF: {}", wif);
        println!("    FP Hash: {:#x}", fp);
    }
    
    println!("\n🎯 Test Validation Instructions:");
    println!("═══════════════════════════════════════════════════════════");
    println!("1. Fund ONE address with minimal testnet BTC (~0.001 tBTC)");
    println!("2. Recommended: Use key #500 (middle of dataset)");
    println!("   Address: {}", vulnerable_keys[500].4);
    println!("   WIF: {}", vulnerable_keys[500].3);
    println!("3. Run scanner with timestamp: {}", vulnerable_keys[500].1);
    println!("4. Scanner should find the funded address");
    println!("\n💡 Get testnet coins: https://testnet-faucet.com/btc-testnet/");
    
    Ok(())
}
