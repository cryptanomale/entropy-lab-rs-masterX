use anyhow::{Context, Result};
use std::path::PathBuf;
use temporal_planetarium_lib::utils::db::TargetDatabase;
use temporal_planetarium_lib::scans::randstorm::integration::RandstormScanner;
use temporal_planetarium_lib::scans::randstorm::fingerprints::Phase;
use temporal_planetarium_lib::scans::randstorm::prng::MathRandomEngine;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    dotenv::dotenv().ok();

    println!("🕵️ Forensic Verifier starting...");
    let db_path = PathBuf::from("data/forensic_targets.db");
    let db = TargetDatabase::new(db_path)?;

    println!("📂 Loading Randstorm candidates from database...");
    let targets = db.query_by_class("randstorm", 10000)?;
    println!("✅ Loaded {} candidates.", targets.len());

    if targets.is_empty() {
        println!("⚠️ No candidates found. Run harvest_temporal first.");
        return Ok(());
    }

    let target_addresses: Vec<String> = targets.iter().map(|t| t.address.clone()).collect();

    println!("🛰️ Initializing Randstorm Scanner...");
    let mut scanner = RandstormScanner::new()?;
    
    println!("🚀 Starting verification scan (Exhaustive Phase 1)...");
    let findings = scanner.scan_with_progress(&target_addresses, Phase::One)?;

    println!("📊 Scan Complete. Findings: {}", findings.len());

    for finding in findings {
        println!("🔥 VULNERABILITY CONFIRMED: {}", finding.address);
        println!("   Config: {:?}", finding.browser_config);
        println!("   Timestamp: {}", finding.timestamp);
        
        db.update_status(&finding.address, "confirmed_vuln")?;
    }

    // Mark others as scanned
    // Note: Simple implementation for test phase. In production we'd track which range was covered.
    for target in targets {
        if target.status == "pending" {
            db.update_status(&target.address, "scanned_safe")?;
        }
    }

    println!("✨ Verification results committed to database.");
    Ok(())
}
