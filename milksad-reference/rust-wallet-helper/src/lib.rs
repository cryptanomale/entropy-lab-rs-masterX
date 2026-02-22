use bitcoin::CompressedPublicKey;
use bitcoin::PublicKey;
use bitcoin::key::PubkeyHash;
use bitcoin::key::Secp256k1;
use bitcoin::script;
use bitcoin::script::ScriptExt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use tiny_keccak::Hasher;
use tiny_keccak::Keccak;

pub const BITCOIN_MAINNET_P2PKH_CONSTANT: u8 = 0x00;
pub const LITECOIN_MAINNET_P2PKH_CONSTANT: u8 = 0x30;
pub const LITECOIN_MAINNET_P2SH_CONSTANT: u8 = 0x32;

pub const BITCOIN_MAINNET_CONSTANT: bitcoin::Network = bitcoin::network::Network::Bitcoin;

pub const BITCOINCASH_HRP: &str = "bitcoincash";

static SECP_ENGINE: OnceLock<Secp256k1<bitcoin::secp256k1::All>> = OnceLock::new();

pub fn secp_engine<'a>() -> &'a Secp256k1<bitcoin::secp256k1::All> {
    SECP_ENGINE.get_or_init(Secp256k1::new)
}

/// Mutex-protected counter with printing mechanism, usable in concurrent threads
pub struct Counter {
    counter: AtomicUsize,
    mask: usize,
}

impl Counter {
    /// A log message is printed every time the counter bitwise-and comparison with `mask` is zero
    pub fn new(mask: usize) -> Self {
        Self {
            counter: AtomicUsize::new(0),
            mask,
        }
    }

    /// Count lines and print progress based on the configured bit mask
    pub fn count_and_print_regularly(&self) {
        let cur = self.counter.fetch_add(1, Ordering::Relaxed);
        if cur & self.mask == 0 {
            println!("Processed {} lines", cur);
        }
    }
}

/// raw access to P2PKH address calculation
pub fn p2pkh_manual_address_calculation(hash: &PubkeyHash, network_byte: u8) -> String {
    // inspired by bitcoin crate address formatting code
    let mut prefixed = [0; 21];
    prefixed[0] = network_byte;
    prefixed[1..].copy_from_slice(hash.as_byte_array());
    bitcoin::base58::encode_check(&prefixed[..])
}

/// raw access to P2SHWPKH address calculation
pub fn p2shwpkh_manual_address_calculation(
    compressed_public_key: &CompressedPublicKey,
    network_byte: u8,
) -> String {
    // re-implement bitcoin crate address formatting code with more flexibility

    let builder = script::Builder::new()
        .push_int_unchecked(0)
        .push_slice(compressed_public_key.wpubkey_hash());
    let script_hash = builder
        .as_script()
        .script_hash()
        .expect("script is less than 520 bytes");

    let mut prefixed = [0; 21];
    prefixed[0] = network_byte;
    prefixed[1..].copy_from_slice(script_hash.as_byte_array());
    bitcoin::base58::encode_check(&prefixed[..])
}

/// Expects an uncompressed pubkey
pub fn get_eth_hex_address_from_pubkey_no_checksum(pubkey: PublicKey) -> String {
    // cut off the leading 0x04 indicator byte
    let eth_pubkey_suffix = &pubkey.to_bytes()[1..];

    // initialize Keccak
    let mut keccak_engine = Keccak::v256();
    let mut keccak_output = [0u8; 32];

    // hash over the uncompressed pubkey
    keccak_engine.update(eth_pubkey_suffix);
    keccak_engine.finalize(&mut keccak_output);

    let mut keccak_output_suffix: [u8; 20] = [0; 20];

    // copy last 20 bytes, as is needed for address generation
    keccak_output_suffix[0..20].copy_from_slice(&keccak_output[12..32]);

    // return hex-encoded address string without "0x" prefix
    // no checksum calculation (case insensitive)
    hex::encode(keccak_output_suffix).to_string()
}

/// Expected to work on valid 1- and 3-prefix addresses
///
/// Expected to fail on bc1-prefix addresses
///
/// Will remove any `bitcoincash:` prefix from the output
pub fn bitcoin_legacy_address_to_bitcoin_cash_cashaddr_format(address: &str) -> String {
    // we're cutting of the hrp later, but it still has to be be correct
    // for the address checksum calculation to work
    let res = match cashaddr::convert::from_legacy(address, BITCOINCASH_HRP) {
        // intermediary result has "bitcoincash:restofaddress" structure
        // get rid of "bitcoincash:" prefix
        Ok(mut addr) => addr.split_off(BITCOINCASH_HRP.len() + 1),
        Err(err) => {
            // debug: verbose error printing
            println!("failed converting address {address} due to {err:?}");
            // return empty string instead
            "".to_string()
        }
    };
    res.to_string()
}

#[cfg(test)]
mod tests {
    use bitcoin::{CompressedPublicKey, PrivateKey, PublicKey};

    use crate::{
        BITCOIN_MAINNET_P2PKH_CONSTANT, LITECOIN_MAINNET_P2PKH_CONSTANT,
        LITECOIN_MAINNET_P2SH_CONSTANT, bitcoin_legacy_address_to_bitcoin_cash_cashaddr_format,
        p2pkh_manual_address_calculation, p2shwpkh_manual_address_calculation, secp_engine,
    };

    #[test]
    fn test_manual_address_calculation() {
        let secp = secp_engine();

        // dummy example key
        let private_key_bytes =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();

        let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&private_key_bytes).unwrap();

        let privkey_compressed = PrivateKey {
            compressed: true,
            network: bitcoin::network::NetworkKind::Main,
            inner: secret_key,
        };

        let pubkey_compressed = privkey_compressed.public_key(secp);
        let pubkey_uncompressed = PublicKey::new_uncompressed(pubkey_compressed.inner);

        // manually construct the format from existing pubkey data
        let pubkey_compressed_secondformat = CompressedPublicKey {
            0: pubkey_compressed.inner,
        };

        let pubkey_uncompressed_pubkey_hash = pubkey_uncompressed.pubkey_hash();
        let pubkey_compressed_pubkey_hash = pubkey_compressed.pubkey_hash();

        // Bitcoin mainnet, uncompressed p2pkh
        assert_eq!(
            p2pkh_manual_address_calculation(
                &pubkey_uncompressed_pubkey_hash,
                BITCOIN_MAINNET_P2PKH_CONSTANT
            ),
            "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
        );

        // Bitcoin mainnet, compressed p2pkh
        assert_eq!(
            p2pkh_manual_address_calculation(
                &pubkey_compressed_pubkey_hash,
                BITCOIN_MAINNET_P2PKH_CONSTANT
            ),
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        );

        // Bitcoin cash mainnet, uncompressed p2pkh
        // via https://secretscan.org/Bitcoin_Cash_address_converter_bech32m
        assert_eq!(
            bitcoin_legacy_address_to_bitcoin_cash_cashaddr_format(
                &p2pkh_manual_address_calculation(
                    &pubkey_uncompressed_pubkey_hash,
                    BITCOIN_MAINNET_P2PKH_CONSTANT
                )
            ),
            "qzgmyjle755g2v5kptrg02asx5f8k8fg55zdx7hd4l"
        );

        // Bitcoin cash mainnet, compressed p2pkh
        // via https://secretscan.org/Bitcoin_Cash_address_converter_bech32m
        assert_eq!(
            bitcoin_legacy_address_to_bitcoin_cash_cashaddr_format(
                &p2pkh_manual_address_calculation(
                    &pubkey_compressed_pubkey_hash,
                    BITCOIN_MAINNET_P2PKH_CONSTANT
                )
            ),
            "qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h"
        );

        // Litecoin mainnet, uncompressed p2pkh
        assert_eq!(
            p2pkh_manual_address_calculation(
                &pubkey_uncompressed_pubkey_hash,
                LITECOIN_MAINNET_P2PKH_CONSTANT
            ),
            "LYWKqJhtPeGyBAw7WC8R3F7ovxtzAiubdM"
        );

        // Litecoin mainnet, compressed p2pkh
        assert_eq!(
            p2pkh_manual_address_calculation(
                &pubkey_compressed_pubkey_hash,
                LITECOIN_MAINNET_P2PKH_CONSTANT
            ),
            "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ"
        );

        // Litecoin mainnet, Segwit base58
        assert_eq!(
            p2shwpkh_manual_address_calculation(
                &pubkey_compressed_secondformat,
                LITECOIN_MAINNET_P2SH_CONSTANT,
            ),
            "MR8UQSBr5ULwWheBHznrHk2jxyxkHQu8vB"
        );
    }
}
