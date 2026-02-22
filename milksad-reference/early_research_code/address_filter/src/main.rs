use clap::{arg, Parser};
use serde_derive::Deserialize;
use std::path::PathBuf;

mod bloom;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Opts {
    /// Read CSV file, see record type for format details
    #[arg(short, long, help = "Input file")]
    input_file: PathBuf,

    /// Output CSV file with matches, mirroring the input format
    #[arg(short, long, help = "Output file")]
    output_file: PathBuf,

    /// bloom filter to check the address strings against
    #[arg(short, long, help = "Bloom filter data file")]
    bloom_file: PathBuf,
}

#[derive(Debug, Deserialize)]
struct AddressRecord {
    index: u32,
    address: String,
}

fn main() {
    let opts: Opts = Opts::parse();

    println!("Loading bloom filter dump ...");
    let bloom = bloom::load(&opts.bloom_file).expect("Failed to load bloom filter");
    println!("... done.");

    let rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(&opts.input_file)
        .expect("Failed to open input_file");

    let mut wtr = csv::Writer::from_path(&opts.output_file).expect("Failed to open output_file");

    let mut count: usize = 0;

    rdr.into_deserialize()
        .for_each(|result: Result<AddressRecord, csv::Error>| {
            if count & 0b1_1111_1111_1111_1111_1111 == 0 {
                println!("Processed {} lines", count);
            }
            count += 1;

            match result {
                Ok(record) => {
                    if bloom.check(&record.address) {
                        wtr.write_record(&[record.index.to_string(), record.address])
                            .unwrap();
                        // avoid problem of delayed output to disk
                        wtr.flush().expect("flush failed");
                    }
                }
                Err(err) => println!("Error reading CSV record: {}", err),
            }
        });

    wtr.flush().expect("flush failed");
}
