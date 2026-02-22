use anyhow::Result;
use bloomfilter::Bloom;
use std::fs::File;
use std::io::{BufRead, BufReader};
use tracing::{info, warn};

/// Build a Bloom Filter from a file of addresses (In-Memory Verify)
pub fn build_from_file(
    input_path: &str,
    output_path: &str,
    expected_items: usize,
    fp_rate: f64,
) -> Result<()> {
    info!(
        "Initializing Bloom Filter (Items: {}, FP Rate: {})",
        expected_items, fp_rate
    );

    // new_for_fp_rate returns Result.
    let mut bloom: Bloom<String> = Bloom::new_for_fp_rate(expected_items, fp_rate)
        .map_err(|e| anyhow::anyhow!("Error creating bloom: {:?}", e))?;

    info!("Reading addresses from {}...", input_path);
    let file = File::open(input_path)?;
    let reader = BufReader::new(file);
    let mut count = 0;

    for line in reader.lines() {
        let line = line?;
        let addr = line.trim();
        if !addr.is_empty() {
            bloom.set(&addr.to_string());
            count += 1;
            if count % 1_000_000 == 0 {
                info!("Processed {} addresses...", count);
            }
        }
    }

    info!("Finished processing {} addresses.", count);
    info!("Bloom Filter populated successfully.");
    warn!("saving to {} is NOT IMPLEMENTED due to serialization limitations in the current crate version.", output_path);
    warn!("Ideally, we would serialize the filter here.");

    Ok(())
}

/// Load a Bloom Filter from a file (Stub)
pub fn load_from_file(_path: &str) -> Result<Bloom<String>> {
    anyhow::bail!("Loading bloom filter not implemented (serialization issue)")
}

/// Check if an address exists in the filter
pub fn check(bloom: &Bloom<String>, address: &str) -> bool {
    bloom.check(&address.to_string())
}
