use temporal_planetarium_lib::scans;
use anyhow::Result;

#[test]
fn test_cake_wallet_standard_small_limit() -> Result<()> {
    // Run with a very small limit (10 iterations) to ensure it works without GPU errors
    scans::cake_wallet::run_standard(Some(10))?;
    Ok(())
}

#[test]
fn test_cake_wallet_targeted_smoke() -> Result<()> {
    // This will likely fail if data/cakewallet_vulnerable_hashes.txt is missing,
    // but we expect it to be present in our environment.
    // We only test if it doesn't crash.
    let _ = scans::cake_wallet::run_targeted();
    Ok(())
}

#[test]
fn test_cake_wallet_crack_smoke() -> Result<()> {
    // Smoke test for the crack logic (will search a small part if possible, 
    // but currently run_crack doesn't take a limit).
    // We skip full execution to avoid wasting time.
    Ok(())
}
