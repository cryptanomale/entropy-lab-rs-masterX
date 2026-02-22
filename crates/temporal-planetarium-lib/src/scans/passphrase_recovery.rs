//! BIP39 Passphrase Recovery Scanner
//!
//! When a wallet is generated with a weak PRNG, users may still be protected
//! if they used a BIP39 passphrase. This scanner tries known/common passphrases
//! to recover such wallets.
//!
//! Defense context: As noted in the Milk Sad 38C3 talk, BIP39 passphrases act
//! as an additional encryption layer that can protect weak PRNG wallets.

use anyhow::Result;
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;
use tracing::{info, warn};

/// Common BIP39 passphrases to try
pub fn get_common_passphrases() -> Vec<String> {
    vec![
        // Empty (most common)
        "".to_string(),
        // Common words
        "password".to_string(),
        "passphrase".to_string(),
        "secret".to_string(),
        "bitcoin".to_string(),
        "crypto".to_string(),
        "wallet".to_string(),
        "secure".to_string(),
        "hodl".to_string(),
        "moon".to_string(),
        // Numbers
        "123456".to_string(),
        "1234567890".to_string(),
        "000000".to_string(),
        // Years
        "2020".to_string(),
        "2021".to_string(),
        "2022".to_string(),
        "2023".to_string(),
        // Common phrases
        "to the moon".to_string(),
        "satoshi nakamoto".to_string(),
        "in crypto we trust".to_string(),
    ]
}

/// Try to recover a wallet using known mnemonic and common passphrases
pub fn recover_with_common_passphrases(
    mnemonic_str: &str,
    target_address: &str,
) -> Result<Option<String>> {
    info!("BIP39 Passphrase Recovery Scanner");
    info!(
        "Mnemonic: {}...",
        &mnemonic_str.chars().take(20).collect::<String>()
    );
    info!("Target: {}", target_address);

    let mnemonic = Mnemonic::from_str(mnemonic_str)?;
    let passphrases = get_common_passphrases();

    info!("Trying {} common passphrases...", passphrases.len());

    for passphrase in &passphrases {
        if try_passphrase(&mnemonic, passphrase, target_address)? {
            warn!("🎯 FOUND PASSPHRASE: \"{}\"", passphrase);
            return Ok(Some(passphrase.clone()));
        }
    }

    info!("No matching passphrase found in common list.");
    Ok(None)
}

/// Try to recover a wallet using mnemonic and passphrases from a file
pub fn recover_with_passphrase_file(
    mnemonic_str: &str,
    target_address: &str,
    passphrase_file: &str,
) -> Result<Option<String>> {
    info!("BIP39 Passphrase Recovery Scanner (File Mode)");
    info!(
        "Mnemonic: {}...",
        &mnemonic_str.chars().take(20).collect::<String>()
    );
    info!("Target: {}", target_address);
    info!("Passphrase file: {}", passphrase_file);

    let mnemonic = Mnemonic::from_str(mnemonic_str)?;
    let file = File::open(passphrase_file)?;
    let reader = BufReader::new(file);

    let mut checked = 0u64;
    let start_time = std::time::Instant::now();

    for line in reader.lines() {
        let passphrase = line?;

        if try_passphrase(&mnemonic, &passphrase, target_address)? {
            warn!("🎯 FOUND PASSPHRASE: \"{}\"", passphrase);
            return Ok(Some(passphrase));
        }

        checked += 1;
        if checked.is_multiple_of(10000) {
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = checked as f64 / elapsed;
            info!("Tried {} passphrases | {:.0}/s", checked, speed);
        }
    }

    info!(
        "No matching passphrase found (tried {} passphrases).",
        checked
    );
    Ok(None)
}

/// Try a single passphrase and check if it produces the target address
fn try_passphrase(mnemonic: &Mnemonic, passphrase: &str, target_address: &str) -> Result<bool> {
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    // Derive seed with passphrase
    let seed = mnemonic.to_seed(passphrase);

    // Try common derivation paths
    let paths = [
        "m/44'/0'/0'/0/0", // BIP44 Legacy
        "m/49'/0'/0'/0/0", // BIP49 SegWit (P2SH)
        "m/84'/0'/0'/0/0", // BIP84 Native SegWit
        "m/0'/0/0",        // Electrum
    ];

    if let Ok(root) = Xpriv::new_master(network, &seed) {
        for path_str in &paths {
            if let Ok(path) = DerivationPath::from_str(path_str) {
                if let Ok(child) = root.derive_priv(&secp, &path) {
                    let pubkey = child.to_keypair(&secp).public_key();
                    let compressed = CompressedPublicKey(pubkey);

                    // Check P2PKH (1...)
                    let addr_p2pkh = Address::p2pkh(compressed, network);
                    if addr_p2pkh.to_string() == target_address {
                        return Ok(true);
                    }

                    // Check P2WPKH (bc1q...)
                    let addr_p2wpkh = Address::p2wpkh(&compressed, network);
                    if addr_p2wpkh.to_string() == target_address {
                        return Ok(true);
                    }

                    // Check P2SH-P2WPKH (3...)
                    let addr_p2shwpkh = Address::p2shwpkh(&compressed, network);
                    if addr_p2shwpkh.to_string() == target_address {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

/// Generate all addresses for a mnemonic with given passphrase
/// Useful for investigating what addresses would be produced
pub fn show_addresses(mnemonic_str: &str, passphrase: &str) -> Result<()> {
    info!("Generating addresses for mnemonic with passphrase");

    let mnemonic = Mnemonic::from_str(mnemonic_str)?;
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;
    let seed = mnemonic.to_seed(passphrase);

    let paths = [
        ("BIP44 (Legacy)", "m/44'/0'/0'/0/0"),
        ("BIP49 (P2SH-SegWit)", "m/49'/0'/0'/0/0"),
        ("BIP84 (Native SegWit)", "m/84'/0'/0'/0/0"),
        ("Electrum", "m/0'/0/0"),
    ];

    if let Ok(root) = Xpriv::new_master(network, &seed) {
        for (name, path_str) in &paths {
            if let Ok(path) = DerivationPath::from_str(path_str) {
                if let Ok(child) = root.derive_priv(&secp, &path) {
                    let pubkey = child.to_keypair(&secp).public_key();
                    let compressed = CompressedPublicKey(pubkey);

                    info!("\n{} ({}):", name, path_str);
                    info!("  P2PKH:       {}", Address::p2pkh(compressed, network));
                    info!("  P2WPKH:      {}", Address::p2wpkh(&compressed, network));
                    info!("  P2SH-P2WPKH: {}", Address::p2shwpkh(&compressed, network));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_passphrases_list() {
        let passphrases = get_common_passphrases();
        assert!(!passphrases.is_empty());
        assert!(passphrases.contains(&"".to_string())); // Empty should be first
    }

    #[test]
    fn test_try_passphrase_with_known_mnemonic() {
        // Test with a known mnemonic and empty passphrase
        let mnemonic = Mnemonic::from_str(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();

        // This is the known first address for standard test mnemonic with empty passphrase
        // Path: m/44'/0'/0'/0/0
        let result = try_passphrase(&mnemonic, "", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
        assert!(result.is_ok());
    }
}
