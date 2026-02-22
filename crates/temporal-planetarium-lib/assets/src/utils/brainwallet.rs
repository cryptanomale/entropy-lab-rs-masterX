use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Network, PrivateKey};
use sha2::{Digest, Sha256};
use anyhow::Result;

/// Derive a Bitcoin P2PKH address from a brainwallet passphrase.
/// Formula: privkey = SHA256(passphrase)
pub fn derive_brainwallet_p2pkh(passphrase: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let result = hasher.finalize();
    
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&result)?;
    let private_key = PrivateKey::new(secret_key, Network::Bitcoin);
    let pubkey = private_key.public_key(&secp);
    
    Ok(Address::p2pkh(pubkey, Network::Bitcoin).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_brainwallet() -> Result<()> {
        // Known vector: SHA256("correct horse battery staple")
        // Passphrase: "correct horse battery staple"
        let addr = derive_brainwallet_p2pkh("correct horse battery staple")?;
        assert!(addr.starts_with('1'));
        Ok(())
    }
}
