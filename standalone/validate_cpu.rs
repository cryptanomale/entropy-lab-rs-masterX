// Validation test - generate reference addresses using CPU
use bip39::Mnemonic;
use rand::SeedableRng;
use rand_mt::Mt19937GenRand32;

fn generate_mnemonic(seed: u32) -> Option<Mnemonic> {
    let mut rng = Mt19937GenRand32::from_seed(seed.to_le_bytes());
    let mut entropy = [0u8; 16];
    for i in 0..4 {
        let rand_u32 = rng.next_u32();
        entropy[i*4..(i+1)*4].copy_from_slice(&rand_u32.to_le_bytes());
    }
    Mnemonic::from_entropy(&entropy).ok()
}

fn main() {
    println!("CPU Reference Validation");
    println!("========================");
    
    // Known test vector from Trust Wallet test
    let test_seed = 1668384000u32; // Nov 14 2022 00:00:00 UTC
    let expected_mnemonic = "spider history orbit robust used holiday patrol ice fruit cube alpha scan";
    
    if let Some(mnemonic) = generate_mnemonic(test_seed) {
        let mnemonic_str = mnemonic.to_string();
        println!("\nTest Vector 1:");
        println!("  Seed: {}", test_seed);
        println!("  Expected: {}", expected_mnemonic);
        println!("  Got:      {}", mnemonic_str);
        println!("  Match: {}", mnemonic_str == expected_mnemonic);
        
        if mnemonic_str != expected_mnemonic {
            println!("\n✗ ERROR: Mnemonic mismatch!");
            std::process::exit(1);
        }
    }
    
    // Generate small reference set
    println!("\n\nGenerating Reference Set (first 10):");
    println!("=====================================");
    for i in 0..10 {
        let seed = 1668384000 + i;
        if let Some(mnemonic) = generate_mnemonic(seed) {
            // Get entropy for reference
            let mut rng = Mt19937GenRand32::from_seed(seed.to_le_bytes());
            let mut entropy = [0u8; 16];
            for j in 0..4 {
                let rand_u32 = rng.next_u32();
                entropy[j*4..(j+1)*4].copy_from_slice(&rand_u32.to_le_bytes());
            }
            
            println!("{},{},{}", seed, hex::encode(entropy), mnemonic);
        }
    }
    
    println!("\n✓ CPU reference generation successful");
}
