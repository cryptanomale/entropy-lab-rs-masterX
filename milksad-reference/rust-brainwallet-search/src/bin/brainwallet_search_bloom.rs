use clap::{Parser, arg};
use rust_brainwallet_search::{Cointype, Hashtype, brainwallet_search};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Opts {
    #[arg(
        short,
        long,
        help = "Input file with newline-separated text snippet candidates"
    )]
    input_file: String,

    #[arg(
        short,
        long,
        help = "Output file in CSV format with information on matches"
    )]
    output_file: String,

    #[arg(
        long,
        help = "Bloom filter file with known addresses of the specified coin type"
    )]
    bloom_file: String,

    #[arg(
        long,
        help = "How many times to use the hashing function",
        default_value_t = 1
    )]
    hashing_rounds: usize,

    #[arg(
        long,
        help = "How many times to repeat the input during hashing. Primitive, may be deprecated soon.",
        default_value_t = 1
    )]
    hasher_input_repetition_count: usize,

    #[arg(
        long,
        help = "Coin type to check",
        default_value_t = Cointype::Bitcoin
    )]
    #[clap(value_enum)]
    cointype: Cointype,

    #[arg(
        long,
        help = "Hash type to use",
        default_value_t = Hashtype::Sha256
    )]
    #[clap(value_enum)]
    hashtype: Hashtype,
}

fn main() {
    let opts: Opts = Opts::parse();
    brainwallet_search(
        &opts.input_file,
        &opts.output_file,
        &opts.bloom_file,
        opts.hashing_rounds,
        opts.hasher_input_repetition_count,
        opts.cointype,
        opts.hashtype,
    );
}
