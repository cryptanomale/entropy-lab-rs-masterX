use clap::{arg, Parser};
use serde_derive::Deserialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Opts {
    /// See the record definition for expected CSV format
    #[arg(short, long, help = "Input file (mnemonics csv)")]
    input_file: PathBuf,

    /// ASCII file with newline-separated hash values
    #[arg(short, long, help = "Output file (sha256 hashes)")]
    output_file: PathBuf,
}

#[derive(Debug, Deserialize)]
struct MnemonicRecord {
    _index: u32,
    mnemonic: String,
}

fn main() {
    let opts: Opts = Opts::parse();

    // Improvement idea: use higher than default capacity?
    let rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(&opts.input_file)
        .expect("Failed to open input_file");

    let wtr = File::create(&opts.output_file).expect("error opening output file");
    let mut wtr = BufWriter::new(wtr);

    let mut count: usize = 0;

    rdr.into_deserialize()
        .for_each(|result: Result<MnemonicRecord, csv::Error>| {
            if count & 0b1_1111_1111_1111_1111_1111 == 0 {
                println!("Processed {} lines", count);
            }
            count += 1;

            match result {
                Ok(record) => {
                    let val = sha256::digest(record.mnemonic);
                    wtr.write_all(val.as_bytes()).expect("write error");
                    wtr.write_all("\n".as_bytes()).expect("write error");
                }
                Err(err) => eprintln!("Error reading CSV record: {}", err),
            }
        });
}
