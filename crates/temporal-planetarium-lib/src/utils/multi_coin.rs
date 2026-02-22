//! Multi-Coin Address Generation
//!
//! Supports generating addresses for:
//! - Bitcoin (BTC): P2PKH, P2SH-SegWit, Native SegWit
//! - Ethereum (ETH): Keccak256-based addresses
//! - Litecoin (LTC): P2PKH with version byte 0x30
//! - Bitcoin Cash (BCH): CashAddr format
//!
//! Based on reference implementation from milksad/rust-wallet-helper

use bitcoin::secp256k1::PublicKey;

// Network version bytes
pub const BITCOIN_P2PKH_VERSION: u8 = 0x00;
pub const BITCOIN_P2SH_VERSION: u8 = 0x05;
pub const LITECOIN_P2PKH_VERSION: u8 = 0x30; // L prefix
pub const LITECOIN_P2SH_VERSION: u8 = 0x32; // M prefix

/// Generate Ethereum address from uncompressed public key
/// Uses Keccak256 hash of the 64-byte public key (without 0x04 prefix)
/// Returns the last 20 bytes as hex string (without 0x prefix)
pub fn eth_address_from_pubkey(pubkey: &PublicKey) -> String {
    use sha3::{Digest as Sha3Digest, Keccak256};

    // Get uncompressed form (65 bytes: 0x04 + 64 bytes)
    let uncompressed = pubkey.serialize_uncompressed();

    // Hash the 64-byte suffix (skip 0x04 prefix)
    let mut hasher = Keccak256::new();
    hasher.update(&uncompressed[1..65]);
    let hash = hasher.finalize();

    // Take last 20 bytes
    let addr_bytes = &hash[12..32];

    hex::encode(addr_bytes)
}

/// Generate Litecoin P2PKH address from compressed public key
pub fn ltc_p2pkh_address(pubkey: &bitcoin::CompressedPublicKey) -> String {
    let pubkey_hash = pubkey.pubkey_hash();
    let hash_bytes: &[u8; 20] = pubkey_hash.as_raw_hash().as_ref();
    p2pkh_from_hash_with_version(hash_bytes, LITECOIN_P2PKH_VERSION)
}

/// Generate Litecoin P2SH-wrapped SegWit address
pub fn ltc_p2shwpkh_address(pubkey: &bitcoin::CompressedPublicKey) -> String {
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};

    // Get witness pubkey hash
    let wpkh = pubkey.wpubkey_hash();
    let wpkh_bytes: &[u8] = wpkh.as_ref();

    // Create redeem script: OP_0 (0x00) + PushBytes20 (0x14) + 20-byte hash
    let mut redeem_script = vec![0x00, 0x14];
    redeem_script.extend_from_slice(wpkh_bytes);

    // Hash the redeem script: SHA256 then RIPEMD160
    let sha256_hash = Sha256::digest(&redeem_script);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha256_hash);
    let hash160_result = ripemd.finalize();

    // Convert to [u8; 20]
    let mut hash_bytes = [0u8; 20];
    hash_bytes.copy_from_slice(&hash160_result);
    p2pkh_from_hash_with_version(&hash_bytes, LITECOIN_P2SH_VERSION)
}

/// Generate P2PKH address with custom version byte
fn p2pkh_from_hash_with_version(hash160: &[u8; 20], version: u8) -> String {
    let mut prefixed = [0u8; 21];
    prefixed[0] = version;
    prefixed[1..].copy_from_slice(hash160);
    bs58::encode(&prefixed).with_check().into_string()
}

/// Generate Bitcoin Cash CashAddr from Legacy address
/// Converts 1... or 3... addresses to q... or p... format
pub fn btc_to_bch_cashaddr(legacy_address: &str) -> Option<String> {
    // Decode base58check
    let decoded = bs58::decode(legacy_address)
        .with_check(None)
        .into_vec()
        .ok()?;
    if decoded.len() != 21 {
        return None;
    }

    let version = decoded[0];
    let hash160: [u8; 20] = decoded[1..21].try_into().ok()?;

    // Determine address type
    let addr_type = match version {
        0x00 => 0, // P2PKH
        0x05 => 1, // P2SH
        _ => return None,
    };

    // CashAddr encoding
    Some(encode_cashaddr("bitcoincash", addr_type, &hash160))
}

/// Encode CashAddr format (simplified implementation)
fn encode_cashaddr(hrp: &str, addr_type: u8, hash160: &[u8; 20]) -> String {
    // Version byte: type (0 or 1) + size indicator (0 for 20 bytes)
    let version_byte = addr_type << 3;

    // Convert to 5-bit groups
    let mut data = vec![version_byte];
    data.extend(convert_8to5(hash160));

    // Compute checksum
    let checksum = cashaddr_checksum(hrp, &data);
    data.extend(&checksum);

    // Encode to base32
    let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let encoded: String = data
        .iter()
        .map(|&b| charset.chars().nth(b as usize).unwrap())
        .collect();

    // Return without prefix for simplicity (like the reference)
    encoded
}

/// Convert bytes from 8-bit to 5-bit groups
fn convert_8to5(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;

    for &byte in data {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(((acc >> bits) & 0x1f) as u8);
        }
    }

    if bits > 0 {
        result.push(((acc << (5 - bits)) & 0x1f) as u8);
    }

    result
}

/// Compute CashAddr checksum
fn cashaddr_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    // Expand HRP
    let mut values: Vec<u64> = hrp.bytes().map(|b| (b & 0x1f) as u64).collect();
    values.push(0);
    values.extend(data.iter().map(|&b| b as u64));
    values.extend(&[0u64; 8]);

    let polymod = cashaddr_polymod(&values) ^ 1;

    (0..8)
        .map(|i| ((polymod >> (5 * (7 - i))) & 0x1f) as u8)
        .collect()
}

/// CashAddr polymod function
fn cashaddr_polymod(values: &[u64]) -> u64 {
    let mut c = 1u64;
    for &v in values {
        let c0 = c >> 35;
        c = ((c & 0x07ffffffff) << 5) ^ v;
        if c0 & 1 != 0 {
            c ^= 0x98f2bc8e61;
        }
        if c0 & 2 != 0 {
            c ^= 0x79b76d99e2;
        }
        if c0 & 4 != 0 {
            c ^= 0xf33e5fb3c4;
        }
        if c0 & 8 != 0 {
            c ^= 0xae2eabe2a8;
        }
        if c0 & 16 != 0 {
            c ^= 0x1e4f43e470;
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    #[test]
    fn test_eth_address_from_privkey_one() {
        // Private key = 1 (well-known test vector)
        let secp = Secp256k1::new();
        let privkey_bytes =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let secret = SecretKey::from_slice(&privkey_bytes).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &secret);

        let eth_addr = eth_address_from_pubkey(&pubkey);
        // Known address for private key 1
        assert_eq!(eth_addr, "7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    #[test]
    fn test_ltc_p2pkh_address_from_privkey_one() {
        let secp = Secp256k1::new();
        let privkey_bytes =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let secret = SecretKey::from_slice(&privkey_bytes).unwrap();
        let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let compressed = bitcoin::CompressedPublicKey(pubkey);

        let ltc_addr = ltc_p2pkh_address(&compressed);
        // Expected: LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ
        assert!(
            ltc_addr.starts_with('L'),
            "LTC P2PKH should start with L, got: {}",
            ltc_addr
        );
    }

    #[test]
    fn test_bch_cashaddr_conversion() {
        // Bitcoin legacy address for private key 1 (uncompressed)
        let legacy = "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm";
        let cashaddr = btc_to_bch_cashaddr(legacy);
        assert!(
            cashaddr.is_some(),
            "Should successfully convert to CashAddr"
        );
    }
}
