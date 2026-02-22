use temporal_planetarium_lib::scans;
use anyhow::Result;

#[test]
fn test_trust_wallet_lcg_smoke() -> Result<()> {
    // Smoke test for LCG with a 1-second range
    let target = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // Not expected to be found
    let _ = scans::trust_wallet::run_lcg(target, 1668384000, 1668384000);
    Ok(())
}

#[test]
fn test_trust_wallet_standard_smoke() -> Result<()> {
    // Standard scanner usually requires GPU and a target. 
    // We verify it doesn't panic immediately.
    let target = Some("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string());
    // We expect this to return an error if GPU is missing, which is also a valid "didn't panic" result
    let _ = scans::trust_wallet::run_standard(target);
    Ok(())
}
