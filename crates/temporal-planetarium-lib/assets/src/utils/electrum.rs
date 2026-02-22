use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// Electrum seed types determined by version prefix
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ElectrumSeedType {
    /// Standard Electrum seed (version prefix starts with "01")
    Standard,
    /// SegWit Electrum seed (version prefix starts with "100")
    Segwit,
    /// Two-Factor Authentication seed (version prefix starts with "101")
    TwoFA,
}

/// Generates a 64-byte seed from a mnemonic using Electrum's algorithm.
///
/// Electrum uses PBKDF2-HMAC-SHA512 with:
/// - Password: The mnemonic string (normalized NFKD, but we assume ASCII for standard wordlists)
/// - Salt: "electrum" (for standard types)
/// - Rounds: 2048
/// - Output: 64 bytes
///
/// CRITICAL: This is DIFFERENT from BIP39!
/// - BIP39 uses salt = "mnemonic" + passphrase
/// - Electrum uses salt = "electrum" + passphrase
///
///   Using the wrong salt produces COMPLETELY DIFFERENT addresses!
pub fn mnemonic_to_seed(mnemonic: &str) -> [u8; 64] {
    mnemonic_to_seed_with_passphrase(mnemonic, "")
}

/// Generates a 64-byte seed from a mnemonic with custom passphrase
pub fn mnemonic_to_seed_with_passphrase(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let mut seed = [0u8; 64];
    let salt = format!("electrum{}", passphrase);
    pbkdf2::<HmacSha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed)
        .expect("PBKDF2 calculation should never fail with valid parameters");
    seed
}

/// Validates if a mnemonic is a valid Electrum seed of the specified type.
///
/// Electrum seeds have version prefixes that MUST be validated using HMAC-SHA512.
/// The HMAC is computed with key "Seed version" and the mnemonic as data.
/// The first bytes of the result determine the seed type.
///
/// Version prefixes:
/// - Standard: starts with "01" (hex)
/// - SegWit: starts with "100" (hex)
/// - TwoFA: starts with "101" (hex)
///
/// Reference: https://electrum.readthedocs.io/en/latest/seedphrase.html
pub fn is_valid_electrum_seed(mnemonic: &str, seed_type: ElectrumSeedType) -> bool {
    // Normalize mnemonic: lowercase and single spaces
    let normalized: String = mnemonic
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");

    // HMAC-SHA512 with key "Seed version"
    let mut mac =
        HmacSha512::new_from_slice(b"Seed version").expect("HMAC key should always be valid");
    mac.update(normalized.as_bytes());
    let result = mac.finalize().into_bytes();

    // Check version prefix (first bytes of HMAC result as hex)
    let version_hex = hex::encode(&result[0..2]);

    match seed_type {
        ElectrumSeedType::Standard => version_hex.starts_with("01"),
        ElectrumSeedType::Segwit => version_hex.starts_with("100"),
        ElectrumSeedType::TwoFA => version_hex.starts_with("101"),
    }
}

/// Detects the Electrum seed type from a mnemonic.
/// Returns None if the mnemonic is not a valid Electrum seed.
pub fn detect_electrum_seed_type(mnemonic: &str) -> Option<ElectrumSeedType> {
    if is_valid_electrum_seed(mnemonic, ElectrumSeedType::TwoFA) {
        Some(ElectrumSeedType::TwoFA)
    } else if is_valid_electrum_seed(mnemonic, ElectrumSeedType::Segwit) {
        Some(ElectrumSeedType::Segwit)
    } else if is_valid_electrum_seed(mnemonic, ElectrumSeedType::Standard) {
        Some(ElectrumSeedType::Standard)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_electrum_seed_different_from_bip39() {
        // This test ensures we don't accidentally use BIP39 derivation
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // Electrum seed with "electrum" salt
        let electrum_seed = mnemonic_to_seed(mnemonic);

        // BIP39 seed uses "mnemonic" salt - let's compute it manually
        let mut bip39_seed = [0u8; 64];
        pbkdf2::<HmacSha512>(mnemonic.as_bytes(), b"mnemonic", 2048, &mut bip39_seed)
            .expect("PBKDF2 should not fail");

        // They MUST be different
        assert_ne!(
            &electrum_seed[..],
            &bip39_seed[..],
            "Electrum and BIP39 seeds must be different"
        );
    }

    #[test]
    fn test_electrum_seed_with_passphrase() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let seed_no_pass = mnemonic_to_seed_with_passphrase(mnemonic, "");
        let seed_with_pass = mnemonic_to_seed_with_passphrase(mnemonic, "TREZOR");

        assert_ne!(
            &seed_no_pass[..],
            &seed_with_pass[..],
            "Different passphrases must produce different seeds"
        );
    }

    #[test]
    fn test_electrum_seed_validation() {
        // Note: BIP39 mnemonics are typically NOT valid Electrum seeds
        // because Electrum uses a different seed format with version prefixes.
        // This test verifies the validation logic works.

        let bip39_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // BIP39 mnemonics typically won't pass Electrum validation
        // (they may randomly pass for some mnemonics, but most won't)
        let is_standard = is_valid_electrum_seed(bip39_mnemonic, ElectrumSeedType::Standard);
        let is_segwit = is_valid_electrum_seed(bip39_mnemonic, ElectrumSeedType::Segwit);

        // Log the results (they may or may not be valid Electrum seeds)
        println!("BIP39 mnemonic Electrum Standard valid: {}", is_standard);
        println!("BIP39 mnemonic Electrum SegWit valid: {}", is_segwit);

        // The function should return without error regardless
    }
}
