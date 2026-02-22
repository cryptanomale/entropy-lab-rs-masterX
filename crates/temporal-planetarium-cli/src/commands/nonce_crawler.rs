// Nonce Reuse Crawler CLI Command
//
// This module provides the CLI interface for the nonce reuse scanner.
// The actual implementation is in temporal-planetarium-lib.

use anyhow::{Context, Result};
use std::path::PathBuf;
use temporal_planetarium_lib::scans::nonce_reuse::{CrawlerConfig, NonceCrawler};
use temporal_planetarium_lib::utils::encryption::DEFAULT_ENCRYPTION_PASSPHRASE;
use tracing::{info, warn};

/// Run the nonce reuse crawler with the given configuration
pub fn run(
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    db_path: PathBuf,
    start_block: Option<u64>,
    end_block: Option<u64>,
    last_n_blocks: Option<u64>,
    resume: bool,
    passphrase: String,
    rate_limit_ms: Option<u64>,
) -> Result<()> {
    info!("🔍 Nonce Reuse Signature Detection Crawler");
    info!("🔗 RPC: {}", rpc_url);
    info!("💾 Database: {}", db_path.display());

    // Security warning if using default passphrase
    if passphrase == DEFAULT_ENCRYPTION_PASSPHRASE {
        warn!("⚠️  WARNING: Using default encryption passphrase. Set NONCE_CRAWLER_PASSPHRASE for production.");
    }

    // Parse RPC URL into host and port
    let (rpc_host, rpc_port) = parse_rpc_url(&rpc_url)?;

    // Build configuration
    let checkpoint_path = db_path.parent()
        .unwrap_or(std::path::Path::new("."))
        .join("nonce_crawler_checkpoint.txt");

    let config = CrawlerConfig {
        rpc_host,
        rpc_port,
        rpc_user,
        rpc_pass,
        db_path,
        passphrase,
        fetch_prevouts: true, // Enable full key recovery
        checkpoint_path: if resume { Some(checkpoint_path.clone()) } else { None },
        checkpoint_interval: 100,
        rate_limit_ms: rate_limit_ms.unwrap_or(50),
    };

    // Create crawler
    let mut crawler = NonceCrawler::new(config)
        .context("Failed to initialize nonce reuse crawler")?;

    // Get current blockchain height
    let blockchain_info = crawler.get_blockchain_info()?;
    let current_height = blockchain_info.blocks;

    // Determine block range
    let (start_height, end_height) = determine_block_range(
        start_block,
        end_block,
        last_n_blocks,
        resume,
        &checkpoint_path,
        current_height,
    )?;

    info!(
        "📊 Scanning blocks {} to {} ({} blocks)",
        start_height,
        end_height,
        end_height - start_height + 1
    );

    // Run the scan
    let stats = crawler.scan_range(start_height, end_height)?;

    info!("✅ Scan complete!");
    info!("   Blocks scanned: {}", stats.blocks_scanned);
    info!("   Signatures parsed: {}", stats.signatures_parsed);
    info!("   Collisions detected: {}", stats.collisions_detected);
    info!("   Keys recovered: {}", stats.keys_recovered);

    Ok(())
}

/// Parse RPC URL into host and port
fn parse_rpc_url(url: &str) -> Result<(String, u16)> {
    let url = url.trim_start_matches("http://").trim_start_matches("https://");
    let parts: Vec<&str> = url.split(':').collect();

    let host = parts.first().unwrap_or(&"127.0.0.1").to_string();
    let port = parts.get(1)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8332);

    Ok((host, port))
}

/// Determine the block range to scan based on CLI args
fn determine_block_range(
    start_block: Option<u64>,
    end_block: Option<u64>,
    last_n_blocks: Option<u64>,
    resume: bool,
    checkpoint_path: &PathBuf,
    current_height: u64,
) -> Result<(u64, u64)> {
    // Priority: resume > explicit range > last_n_blocks > default
    if resume {
        if let Ok(content) = std::fs::read_to_string(checkpoint_path) {
            if let Ok(checkpoint) = content.trim().parse::<u64>() {
                info!("📍 Resuming from checkpoint: block {}", checkpoint);
                let start = checkpoint + 1;
                let end = end_block.unwrap_or(current_height);
                return Ok((start, end));
            }
        }
        return Err(anyhow::anyhow!("No checkpoint found at {:?}", checkpoint_path));
    }

    if let (Some(start), Some(end)) = (start_block, end_block) {
        return Ok((start, end));
    }

    if let Some(start) = start_block {
        let end = end_block.unwrap_or(current_height);
        return Ok((start, end));
    }

    if let Some(n) = last_n_blocks {
        let start = current_height.saturating_sub(n - 1);
        return Ok((start, current_height));
    }

    // Default: last 1000 blocks
    let start = current_height.saturating_sub(999);
    Ok((start, current_height))
}
