use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network};

use bloom::{BloomFilter, ASMS};
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::info;

struct Hit {
    timestamp: u64,
    seed: u32,
    mnemonic: String,
    address: String,
    deriv_type: String,
}

use flate2::read::GzDecoder;

#[derive(Debug, serde::Deserialize)]
struct CsvRow {
    #[serde(rename = "Timestamp_MS")]
    timestamp_ms: u64,
    #[serde(rename = "Seed_u32")]
    seed_u32: u32,
    #[serde(rename = "Mnemonic")]
    mnemonic: String,
}

pub fn run(csv_path: &str, address_list_path: &str) -> Result<()> {
    info!("Loading funded addresses from '{}'...", address_list_path);
    let file = File::open(address_list_path).context("Failed to open address list")?;

    let reader: Box<dyn BufRead> = if address_list_path.ends_with(".gz") {
        Box::new(BufReader::new(GzDecoder::new(file)))
    } else {
        Box::new(BufReader::new(file))
    };

    // Bloom filter setup
    let expected_items = 60_000_000;
    let rate = 0.000001;
    let mut bloom = BloomFilter::with_rate(rate, expected_items);

    info!("Building Bloom filter...");
    let mut count = 0;
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if i == 0 && (line.starts_with("address") || line.starts_with("Address")) {
            continue;
        }

        let addr = if line.contains('\t') {
            line.split('\t').next().unwrap_or("").trim()
        } else {
            line.trim()
        };

        if !addr.is_empty() {
            bloom.insert(&addr.as_bytes());
            count += 1;
        }
    }

    info!("Loaded {} addresses into Bloom filter.", count);

    info!("Opening CSV '{}'...", csv_path);
    let file = File::open(csv_path).context("Failed to open CSV file")?;
    let mut rdr = csv::Reader::from_reader(file);

    let secp = Secp256k1::new();
    // Store potential hits in memory first (Address -> Mnemonic/Info)
    // We store the full CSV line info as a formatted string for easy retrieval later,
    // or just store the address and map it back?
    // Storing "Address" -> "CSV Row Info" allows us to output the CSV row later.
    // But we might have multiple hits for one address? Unlikely for this use case.
    // Let's store "Address" -> "Full CSV Line String"
    // We also need to store the details to write to the file.
    // Let's use a HashMap<Address, Vec<Details>>?
    // To keep it simple and memory efficient, let's just store the *Address* in the HashSet for fast lookup during verification,
    // and store the *Details* in a separate Vec.
    // Actually, we only need to verify if the address exists.
    // Let's store the *Details* in a Vec, and the *Address* is part of it.
    // But we need to quickly check if a line in the address list matches a hit.
    // So:
    // 1. Scan CSV -> If Bloom hit -> Store (Address, FullRowDetails) in a list.
    // 2. After scan -> If list not empty -> Create HashSet of Addresses from list.
    // 3. Scan Address File -> If address in HashSet -> Mark as Confirmed.
    // 4. Filter list for Confirmed addresses -> Write to file.

    let hits: Arc<Mutex<Vec<Hit>>> = Arc::new(Mutex::new(Vec::new()));

    info!("Starting verification...");

    let start = Instant::now();
    let batch_size = 10000;
    let mut batch = Vec::with_capacity(batch_size);
    let mut total_processed: u64 = 0;

    for result in rdr.deserialize() {
        let record: CsvRow = result?;
        batch.push(record);

        if batch.len() >= batch_size {
            process_batch(&batch, &bloom, &secp, &hits)?;
            total_processed += batch.len() as u64;
            let elapsed = start.elapsed().as_secs_f64();
            let speed = total_processed as f64 / elapsed;
            info!(
                "Processed {} addresses... (Speed: {:.2} rows/sec, Time: {:.0}s)",
                total_processed, speed, elapsed
            );
            batch.clear();
        }
    }

    if !batch.is_empty() {
        process_batch(&batch, &bloom, &secp, &hits)?;
    }

    let potential_hits = hits
        .lock()
        .expect("Failed to lock hits mutex - this indicates a critical threading issue");
    info!(
        "Scan complete. Found {} potential hits (Bloom filter matches).",
        potential_hits.len()
    );

    if potential_hits.is_empty() {
        info!("No hits found. Exiting.");
        return Ok(());
    }

    info!("Verifying potential hits against exact address list...");

    // Build a HashSet of the potential addresses for O(1) lookup
    let potential_addr_set: HashSet<String> =
        potential_hits.iter().map(|h| h.address.clone()).collect();
    let mut confirmed_addresses = HashSet::new();

    // Re-read address list
    let file =
        File::open(address_list_path).context("Failed to open address list for verification")?;
    let reader: Box<dyn BufRead> = if address_list_path.ends_with(".gz") {
        Box::new(BufReader::new(GzDecoder::new(file)))
    } else {
        Box::new(BufReader::new(file))
    };

    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if i == 0 && (line.starts_with("address") || line.starts_with("Address")) {
            continue;
        }
        let addr = if line.contains('\t') {
            line.split('\t').next().unwrap_or("").trim()
        } else {
            line.trim()
        };

        if potential_addr_set.contains(addr) {
            confirmed_addresses.insert(addr.to_string());
        }
    }

    info!(
        "Verification complete. Confirmed {} valid hits.",
        confirmed_addresses.len()
    );

    if !confirmed_addresses.is_empty() {
        let mut file = File::create("verified_hits.csv")?;
        writeln!(file, "Timestamp_MS,Seed_u32,Mnemonic,Address,Type")?;
        for hit in potential_hits.iter() {
            if confirmed_addresses.contains(&hit.address) {
                writeln!(
                    file,
                    "{},{},{},{},{}",
                    hit.timestamp, hit.seed, hit.mnemonic, hit.address, hit.deriv_type
                )?;
            }
        }
        info!("Confirmed hits written to 'verified_hits.csv'.");
    } else {
        info!("All potential hits were false positives.");
    }

    Ok(())
}

fn process_batch(
    batch: &[CsvRow],
    bloom: &BloomFilter,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    hits: &Arc<Mutex<Vec<Hit>>>,
) -> Result<()> {
    // Thread-local storage for hits to reduce mutex contention
    let batch_hits = batch
        .par_iter()
        .flat_map(|row| {
            let mut local_hits = Vec::new();
            if let Ok(mnemonic) = Mnemonic::parse_in(Language::English, &row.mnemonic) {
                let seed = mnemonic.to_seed("");
                if let Ok(root) = Xpriv::new_master(Network::Bitcoin, &seed) {
                    let paths = [
                        ("m/44'/0'/0'/0/0", "Legacy"),
                        ("m/84'/0'/0'/0/0", "SegWit"),
                        ("m/49'/0'/0'/0/0", "Nested SegWit"),
                        ("m/86'/0'/0'/0/0", "Taproot"),
                    ];

                    for (base_path_str, type_name) in paths {
                        if let Ok(path) = DerivationPath::from_str(base_path_str) {
                            if let Ok(child) = root.derive_priv(secp, &path) {
                                let pubkey = child.private_key.public_key(secp);
                                let compressed_pk = CompressedPublicKey(pubkey);

                                let address = match type_name {
                                    "Legacy" => Address::p2pkh(compressed_pk, Network::Bitcoin),
                                    "SegWit" => Address::p2wpkh(&compressed_pk, Network::Bitcoin),
                                    "Nested SegWit" => {
                                        Address::p2shwpkh(&compressed_pk, Network::Bitcoin)
                                    }
                                    "Taproot" => {
                                        let (x_only, _parity) = pubkey.x_only_public_key();
                                        Address::p2tr(secp, x_only, None, Network::Bitcoin)
                                    }
                                    _ => continue,
                                };

                                if bloom.contains(&address.to_string().as_bytes()) {
                                    local_hits.push(Hit {
                                        timestamp: row.timestamp_ms,
                                        seed: row.seed_u32,
                                        mnemonic: row.mnemonic.clone(),
                                        address: address.to_string(),
                                        deriv_type: type_name.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            local_hits
        })
        .collect::<Vec<_>>();

    if !batch_hits.is_empty() {
        let mut global_hits = hits
            .lock()
            .expect("Failed to lock hits mutex - this indicates a critical threading issue");
        global_hits.extend(batch_hits);
    }

    Ok(())
}
