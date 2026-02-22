use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn test_cli_help() {
    // This test ensures the binary compiles and runs, and prints help
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("entropy-lab-rs"));
    cmd.arg("--help");
    cmd.assert().success().stdout(predicate::str::contains(
        "Research tool for wallet vulnerabilities",
    ));
}

#[test]
fn test_cli_no_args() {
    // Running without args should fail (clap requires subcommand) or print help
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("entropy-lab-rs"));
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Usage: entropy-lab-rs <COMMAND>"));
}

#[test]
fn test_cake_wallet_cpu_scan_integration() {
    // Run a small scan (only 10 seeds) to verify it doesn't panic and produces output
    // Note: We are testing the library function directly here, not the CLI command.
    // This requires 'entropy-lab-rs' to be a library crate exposing 'scans'.
    let result = temporal_planetarium_lib::scans::cake_wallet::run(Some(10));
    assert!(result.is_ok(), "Cake Wallet CPU scan failed");
}

/// Test BIP49 addresses with 24-word mnemonics for Research Update #13
#[test]
fn test_research_update_13_requirements() {
    use temporal_planetarium_lib::scans::milk_sad::{
        generate_address_from_entropy_vec, generate_entropy_msb, AddressType, EntropySize,
    };

    // Test 1: 256-bit entropy (24 words)
    let entropy = generate_entropy_msb(1234567890, EntropySize::Bits256);
    assert_eq!(entropy.len(), 32, "256-bit entropy should be 32 bytes");

    // Test 2: BIP49 P2SH-SegWit addresses (prefix '3')
    let address = generate_address_from_entropy_vec(&entropy, 0, AddressType::P2SHWPKH, false);
    assert!(
        address.starts_with('3'),
        "BIP49 addresses should start with '3', got: {}",
        address
    );
    println!("✓ BIP49 address generated: {}", address);

    // Test 3: Verify all combinations work
    for entropy_size in [
        EntropySize::Bits128,
        EntropySize::Bits192,
        EntropySize::Bits256,
    ] {
        for addr_type in [
            AddressType::P2PKH,
            AddressType::P2SHWPKH,
            AddressType::P2WPKH,
        ] {
            for change in [false, true] {
                let e = generate_entropy_msb(1500000000, entropy_size);
                let a = generate_address_from_entropy_vec(&e, 0, addr_type, change);
                assert!(!a.is_empty(), "Address should not be empty");
            }
        }
    }

    println!("✓ All Research Update #13 requirements validated!");
}
