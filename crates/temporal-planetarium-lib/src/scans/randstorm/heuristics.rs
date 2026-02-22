use crate::utils::brainwallet::derive_brainwallet_p2pkh;
use crate::scans::milk_sad::{generate_entropy_msb, EntropySize, AddressType, generate_address_from_entropy_vec};
use anyhow::Result;
use std::str::FromStr;

/// Generate heuristic variations of a passphrase.
/// Currently supports:
/// - Case variations (lower, upper, title)
/// - Trimming whitespace
pub fn generate_passphrase_variations(passphrase: &str) -> Vec<String> {
    let mut variations = Vec::new();
    let trimmed = passphrase.trim();
    
    variations.push(trimmed.to_string());
    variations.push(trimmed.to_lowercase());
    variations.push(trimmed.to_uppercase());
    
    // Simple title case (first letter of each word capitalized)
    let title_case = trimmed.split_whitespace()
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<Vec<String>>()
        .join(" ");
    variations.push(title_case);
    
    // Sort and remove duplicates
    variations.sort();
    variations.dedup();
    
    variations
}

/// Generate target addresses from intelligence entries using heuristics.
pub fn generate_heuristic_targets(passphrase: &str) -> Result<Vec<(String, String)>> {
    let variations = generate_passphrase_variations(passphrase);
    let mut targets = Vec::new();
    
    for var in variations {
        if let Ok(addr) = derive_brainwallet_p2pkh(&var) {
            targets.push((addr, var));
        }
    }
    
    Ok(targets)
}

/// Check if a given timestamp (in ms) would have produced a vulnerable Milk Sad wallet.
/// This detects cases where a user might have used Libbitcoin (bx 3.x) around the same time.
pub fn check_milk_sad_correlation(timestamp_ms: u64, target_addr: &str) -> Option<String> {
    let timestamp_s = (timestamp_ms / 1000) as u32;
    
    // Check common bx seed lengths: 128, 192, 256
    let sizes = [EntropySize::Bits128, EntropySize::Bits192, EntropySize::Bits256];
    let types = [AddressType::P2PKH, AddressType::P2SHWPKH, AddressType::P2WPKH];
    
    for size in sizes {
        let entropy = generate_entropy_msb(timestamp_s, size);
        for addr_type in types {
            // Check index 0, external chain
            let derived = generate_address_from_entropy_vec(&entropy, 0, addr_type, false);
            if derived == target_addr {
                return Some(format!("Milk Sad ({:?}, {:?})", size, addr_type));
            }
        }
    }
    
    None
}

/// Check if a given timestamp generates any Milk Sad addresses present in the target hash set.
/// Returns a list of (address_string, info_string) tuples for any hits.
pub fn check_milk_sad_against_hashes(
    timestamp_ms: u64,
    target_hashes: &[Vec<u8>],
) -> Vec<(String, String)> {
    let timestamp_s = (timestamp_ms / 1000) as u32;
    let mut hits = Vec::new();
    
    let sizes = [EntropySize::Bits128, EntropySize::Bits192, EntropySize::Bits256];
    let types = [AddressType::P2PKH, AddressType::P2SHWPKH, AddressType::P2WPKH];
    
    for size in sizes {
        let entropy = generate_entropy_msb(timestamp_s, size);
        for addr_type in types {
            // Index 0, external chain
            let derived_addr = generate_address_from_entropy_vec(&entropy, 0, addr_type, false);
            
            // Convert to hash160 for comparison
            // Note: This re-parses the address which is slightly inefficient but safe.
            // In a tight loop, we might want to optimize this to skip string allocs.
            if let Ok(addr) = bitcoin::Address::from_str(&derived_addr) {
                let addr = addr.assume_checked();
                let script = addr.script_pubkey();
                let hash_bytes = if script.is_p2pkh() {
                    Some(&script.as_bytes()[3..23])
                } else if script.is_p2sh() {
                    Some(&script.as_bytes()[2..22])
                } else {
                    None
                };
                
                if let Some(h) = hash_bytes {
                    for target in target_hashes {
                        if h == target.as_slice() {
                            hits.push((
                                derived_addr.clone(),
                                format!("Milk Sad ({:?}, {:?})", size, addr_type)
                            ));
                            break; // Stop checking targets for this specific derived address
                        }
                    }
                }
            }
        }
    }
    
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passphrase_variations() {
        let vars = generate_passphrase_variations("  Hello World  ");
        assert!(vars.contains(&"Hello World".to_string()));
        assert!(vars.contains(&"hello world".to_string()));
        assert!(vars.contains(&"HELLO WORLD".to_string()));
    }
}
