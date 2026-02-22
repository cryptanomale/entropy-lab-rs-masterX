use bitcoin::Address;
use bitcoin::CompressedPublicKey;
use bitcoin::PrivateKey;
use bitcoin::PublicKey;
use bitcoin::secp256k1::Secp256k1;
use bloomfilter::Bloom;
use rayon::prelude::*;
use rust_wallet_helper::BITCOIN_MAINNET_CONSTANT;
use rust_wallet_helper::Counter;
use rust_wallet_helper::LITECOIN_MAINNET_P2PKH_CONSTANT;
use rust_wallet_helper::LITECOIN_MAINNET_P2SH_CONSTANT;
use rust_wallet_helper::bitcoin_legacy_address_to_bitcoin_cash_cashaddr_format;
use rust_wallet_helper::get_eth_hex_address_from_pubkey_no_checksum;
use rust_wallet_helper::p2pkh_manual_address_calculation;
use rust_wallet_helper::p2shwpkh_manual_address_calculation;
use sha2::Digest;
use sha2::Sha256;
use sha3::Sha3_256;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::sync::Mutex;
use std::sync::OnceLock;

static SECP_ENGINE: OnceLock<Secp256k1<bitcoin::secp256k1::All>> = OnceLock::new();

pub fn secp_engine<'a>() -> &'a Secp256k1<bitcoin::secp256k1::All> {
    SECP_ENGINE.get_or_init(Secp256k1::new)
}
// minor performance tuning: use larger buffer size then default 8KiB
const BUF_READER_CAPACITY: usize = 1_048_576; // 1MiB

/// Type of hashing that should be done for the brainwallet conversion,
/// hash(input) -> private key
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Hashtype {
    Sha256,
    Sha3_256,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Cointype {
    /// Bitcoin mainnet
    Bitcoin,
    /// Litecoin mainnet
    Litecoin,
    /// Bitcoin Cash mainnet
    BitcoinCash,
    /// Ethereum mainnet
    Ethereum,
}

pub fn check_brainwallet_bloom_and_record_hits(
    bloom: &Bloom<String>,
    query: String,
    writer: &Mutex<csv::Writer<std::fs::File>>,
    source_id: String,
    source_id2: String,
    hashing_rounds: String,
    cointype: String,
    compressed_status: String,
    bit_length: String,
    passphrase: String,
    print_hit: bool,
) {
    if bloom.check(&query) {
        if print_hit {
            // quick visual representation of a match
            // see actual data output for details
            println!("hit: {}", query);
        }
        let mut wtr = writer.lock().unwrap();

        wtr.write_record([
            source_id,
            source_id2,
            hashing_rounds,
            cointype,
            compressed_status,
            bit_length,
            passphrase,
            query,
        ])
        .unwrap();
        wtr.flush().expect("flush failed");
    }
}

/// Sanity check on hashing rounds.
/// Panics on problematic values.
pub fn check_hashing_rounds_or_panic(hashing_rounds: usize) {
    if hashing_rounds == 0 {
        panic!("Invalid number of hashing rounds");
    }
}

/// Hashtype to string representation
pub fn get_hashtype_source_id(hashtype: &Hashtype) -> String {
    match hashtype {
        Hashtype::Sha256 => "brainwallet-sha256".to_string(),
        Hashtype::Sha3_256 => "brainwallet-sha3-256".to_string(),
    }
}

fn load_bloom_and_print_or_panic(filepath: &String) -> Bloom<String> {
    println!("Loading bloom filter dump ...");
    let bloom = address_filter::bloom::load(std::path::Path::new(filepath))
        .expect("Couldn't load bloom filter dump, abort");
    println!("... done.");

    bloom
}

pub fn adjust_passphrase_for_repetition(
    passphrase: &String,
    hasher_repetition_count: usize,
) -> String {
    match hasher_repetition_count {
        // 0 should not happen
        0 => "".to_string(),
        1 => passphrase.to_string(),
        other_count => {
            let mut effective_passphrase = "".to_owned();
            for _i in 0..other_count {
                // append the passphrase N times
                effective_passphrase.push_str(passphrase);
            }
            effective_passphrase
        }
    }
}

/// Perform the brain wallet hashing
/// Output size dependent on hash, but currently 256 bit
pub fn compute_hashing(hashtype: &Hashtype, passphrase: &String, hashing_rounds: usize) -> Vec<u8> {
    // write input message
    // TODO this approach of input-to-hashing processing essentially strips some
    // non-printable characters, causing anomalies or missed hits if the input
    // contains those.
    //
    // TODO consider a different data conversion approach

    match hashtype {
        Hashtype::Sha256 => {
            let mut hasher = Sha256::new();

            hasher.update(passphrase.clone());
            // read hash digest and consume hasher
            let mut intermediary = hasher.finalize();

            // if we're asked to do more than one hashing round, repeat the hashing
            // this is inefficient and designed for a low number of rounds
            for _i in 1..hashing_rounds {
                intermediary = Sha256::digest(intermediary);
            }
            return intermediary.to_vec();
        }
        Hashtype::Sha3_256 => {
            let mut hasher = Sha3_256::new();

            hasher.update(passphrase.clone());

            // read hash digest and consume hasher
            let mut intermediary = hasher.finalize();

            // if we're asked to do more than one hashing round, repeat the hashing
            // this is inefficient and designed for a low number of rounds
            for _i in 1..hashing_rounds {
                intermediary = Sha3_256::digest(intermediary);
            }
            return intermediary.to_vec();
        }
    }
}

/// Generic function to do the search
pub fn brainwallet_search(
    input_file: &String,
    output_file: &String,
    bloom_file: &String,
    hashing_rounds: usize,
    hasher_repetition_count: usize,
    cointype: Cointype,
    hashtype: Hashtype,
) {
    match cointype {
        Cointype::Bitcoin => {
            brainwallet_sha256_check_btc(
                input_file,
                output_file,
                bloom_file,
                hashing_rounds,
                hasher_repetition_count,
                hashtype,
            );
        }
        Cointype::BitcoinCash => {
            brainwallet_sha256_check_bitcoin_cash_cashaddr(
                input_file,
                output_file,
                bloom_file,
                hashing_rounds,
                hasher_repetition_count,
                hashtype,
            );
        }
        Cointype::Litecoin => {
            brainwallet_sha256_check_ltc(
                input_file,
                output_file,
                bloom_file,
                hashing_rounds,
                hasher_repetition_count,
                hashtype,
            );
        }
        Cointype::Ethereum => {
            brainwallet_sha256_check_eth(
                input_file,
                output_file,
                bloom_file,
                hashing_rounds,
                hasher_repetition_count,
                hashtype,
            );
        }
    }
}

pub fn brainwallet_sha256_check_btc(
    input_file: &String,
    output_file: &String,
    btc_bloom: &String,
    hashing_rounds: usize,
    hasher_repetition_count: usize,
    hashtype: Hashtype,
) {
    check_hashing_rounds_or_panic(hashing_rounds);
    let file = File::open(input_file).unwrap();
    let wtr = Mutex::new(csv::Writer::from_path(output_file).unwrap());

    let bloom = load_bloom_and_print_or_panic(btc_bloom);

    // log every 2^19 lines
    let c = Counter::new(0b0111_1111_1111_1111_1111);

    let secp = secp_engine();

    let source_id = get_hashtype_source_id(&hashtype);
    let source_id2 = "direct";
    let coin_type = "btc";

    // silently drop any problematic lines
    // TODO replace with a mode that flags problematic inputs and keeps statistics on them
    //
    // This distributes inputs on the fly to the parallel runners,
    // avoiding the need to load the initial input file completely into memory first
    BufReader::with_capacity(BUF_READER_CAPACITY, file)
        .lines()
        .par_bridge()
        .filter_map(|l| l.ok())
        .for_each(|passphrase| {
            // Count lines and print progress
            c.count_and_print_regularly();

            let effective_passphrase =
                adjust_passphrase_for_repetition(&passphrase, hasher_repetition_count);

            let entropy = compute_hashing(&hashtype, &effective_passphrase, hashing_rounds);

            let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&entropy[..]).unwrap();

            // Convert SecretKey to PrivateKey
            let privkey_compressed = PrivateKey {
                compressed: true,
                network: bitcoin::network::NetworkKind::Main,
                inner: secret_key,
            };

            let pubkey_compressed = privkey_compressed.public_key(secp);
            let pubkey_uncompressed = PublicKey::new_uncompressed(pubkey_compressed.inner);

            // manually construct the format from existing pubkey data
            let pubkey_compressed_secondformat = CompressedPublicKey {
                0: pubkey_compressed.inner,
            };

            // P2PKH with compressed pubkey is seen occasionally
            let address_from_compressed_pubkey =
                Address::p2pkh(&pubkey_compressed, BITCOIN_MAINNET_CONSTANT).to_string();

            check_brainwallet_bloom_and_record_hits(
                &bloom,
                address_from_compressed_pubkey.to_string(),
                &wtr,
                source_id.to_string(),
                source_id2.to_string(),
                hashing_rounds.to_string(),
                coin_type.to_string(),
                "uncompressed".to_string(),
                "256".to_string(),
                effective_passphrase.to_string(),
                true,
            );

            // P2PKH with uncompressed pubkey is the most commonly seen result
            let address_from_uncompressed_pubkey =
                Address::p2pkh(&pubkey_uncompressed, BITCOIN_MAINNET_CONSTANT).to_string();

            check_brainwallet_bloom_and_record_hits(
                &bloom,
                address_from_uncompressed_pubkey.to_string(),
                &wtr,
                source_id.to_string(),
                source_id2.to_string(),
                hashing_rounds.to_string(),
                coin_type.to_string(),
                "uncompressed".to_string(),
                "256".to_string(),
                effective_passphrase.to_string(),
                true,
            );

            // // P2SHWPKH is rare, but seen in the wild
            let address =
                Address::p2shwpkh(pubkey_compressed_secondformat, BITCOIN_MAINNET_CONSTANT)
                    .to_string();

            check_brainwallet_bloom_and_record_hits(
                &bloom,
                address.to_string(),
                &wtr,
                source_id.to_string(),
                source_id2.to_string(),
                hashing_rounds.to_string(),
                coin_type.to_string(),
                "compressed".to_string(),
                "256".to_string(),
                effective_passphrase.to_string(),
                true,
            );

            // P2WPKH is rare, but seen in the wild
            let address = Address::p2wpkh(pubkey_compressed_secondformat, BITCOIN_MAINNET_CONSTANT)
                .to_string();

            check_brainwallet_bloom_and_record_hits(
                &bloom,
                address.to_string(),
                &wtr,
                source_id.to_string(),
                source_id2.to_string(),
                hashing_rounds.to_string(),
                coin_type.to_string(),
                "compressed".to_string(),
                "256".to_string(),
                effective_passphrase.to_string(),
                true,
            );

            // experimentally check for basic P2TR format
            // this is expected to be very rare
            // calculating this address is fairly expensive
            // TODO generalize hrp
            let address = Address::p2tr(&secp, pubkey_compressed, None, bitcoin::KnownHrp::Mainnet)
                .to_string();
            check_brainwallet_bloom_and_record_hits(
                &bloom,
                address.to_string(),
                &wtr,
                source_id.to_string(),
                source_id2.to_string(),
                hashing_rounds.to_string(),
                coin_type.to_string(),
                "compressed".to_string(),
                "256".to_string(),
                effective_passphrase.to_string(),
                true,
            );
        });

    // ensure flush
    wtr.into_inner().unwrap().flush().unwrap();
}

pub fn brainwallet_sha256_check_bitcoin_cash_cashaddr(
    input_file: &String,
    output_file: &String,
    bch_bloom: &String,
    hashing_rounds: usize,
    hasher_repetition_count: usize,
    hashtype: Hashtype,
) {
    check_hashing_rounds_or_panic(hashing_rounds);
    let file = File::open(input_file).unwrap();
    let wtr = Mutex::new(csv::Writer::from_path(output_file).unwrap());

    let bloom = load_bloom_and_print_or_panic(bch_bloom);

    // log every 2^19 lines
    let c = Counter::new(0b0111_1111_1111_1111_1111);

    let secp = secp_engine();

    let source_id = get_hashtype_source_id(&hashtype);
    let source_id2 = "direct";
    let coin_type = "bch";

    // silently drop any problematic lines
    // TODO replace with a mode that flags problematic inputs and keeps statistics on them
    //
    // This distributes inputs on the fly to the parallel runners,
    // avoiding the need to load the initial input file completely into memory first
    BufReader::with_capacity(BUF_READER_CAPACITY, file)
        .lines()
        .par_bridge()
        .filter_map(|l| l.ok())
        .for_each(|passphrase| {
            // Count lines and print progress
            c.count_and_print_regularly();

            let effective_passphrase =
                adjust_passphrase_for_repetition(&passphrase, hasher_repetition_count);

            let entropy = compute_hashing(&hashtype, &effective_passphrase, hashing_rounds);

            let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&entropy[..]).unwrap();

            // Convert SecretKey to PrivateKey
            let privkey_compressed = PrivateKey {
                compressed: true,
                network: bitcoin::network::NetworkKind::Main,
                inner: secret_key,
            };

            let pubkey_compressed = privkey_compressed.public_key(secp);
            let pubkey_uncompressed = PublicKey::new_uncompressed(pubkey_compressed.inner);

            // manually construct the format from existing pubkey data
            let pubkey_compressed_secondformat = CompressedPublicKey {
                0: pubkey_compressed.inner,
            };

            // P2PKH
            let address_from_compressed_pubkey =
                Address::p2pkh(&pubkey_compressed, BITCOIN_MAINNET_CONSTANT).to_string();

            let bitcoin_cash_address1 = bitcoin_legacy_address_to_bitcoin_cash_cashaddr_format(
                &address_from_compressed_pubkey.clone(),
            );
            check_brainwallet_bloom_and_record_hits(
                &bloom,
                bitcoin_cash_address1.to_string(),
                &wtr,
                source_id.to_string(),
                source_id2.to_string(),
                hashing_rounds.to_string(),
                coin_type.to_string(),
                "compressed".to_string(),
                "256".to_string(),
                effective_passphrase.to_string(),
                true,
            );

            // P2PKH
            let address_from_uncompressed_pubkey =
                Address::p2pkh(&pubkey_uncompressed, BITCOIN_MAINNET_CONSTANT).to_string();

            let bitcoin_cash_address2 = bitcoin_legacy_address_to_bitcoin_cash_cashaddr_format(
                &address_from_uncompressed_pubkey.clone(),
            );
            check_brainwallet_bloom_and_record_hits(
                &bloom,
                bitcoin_cash_address2.to_string(),
                &wtr,
                source_id.to_string(),
                source_id2.to_string(),
                hashing_rounds.to_string(),
                coin_type.to_string(),
                "uncompressed".to_string(),
                "256".to_string(),
                effective_passphrase.to_string(),
                true,
            );

            // P2SHWPKH
            let address =
                Address::p2shwpkh(pubkey_compressed_secondformat, BITCOIN_MAINNET_CONSTANT)
                    .to_string();

            let bitcoin_cash_address3 =
                bitcoin_legacy_address_to_bitcoin_cash_cashaddr_format(&address.clone());
            check_brainwallet_bloom_and_record_hits(
                &bloom,
                bitcoin_cash_address3.to_string(),
                &wtr,
                source_id.to_string(),
                source_id2.to_string(),
                hashing_rounds.to_string(),
                coin_type.to_string(),
                "compressed".to_string(),
                "256".to_string(),
                effective_passphrase.to_string(),
                true,
            );
        });

    // ensure flush
    wtr.into_inner().unwrap().flush().unwrap();
}

pub fn brainwallet_sha256_check_ltc(
    input_file: &String,
    output_file: &String,
    ltc_bloom: &String,
    hashing_rounds: usize,
    hasher_repetition_count: usize,
    hashtype: Hashtype,
) {
    check_hashing_rounds_or_panic(hashing_rounds);
    let file = File::open(input_file).unwrap();
    let wtr = Mutex::new(csv::Writer::from_path(output_file).unwrap());

    let bloom = load_bloom_and_print_or_panic(ltc_bloom);

    // log every 2^19 lines
    let c = Counter::new(0b0111_1111_1111_1111_1111);

    let secp = secp_engine();

    let source_id = get_hashtype_source_id(&hashtype);
    let source_id2 = "direct";
    let coin_type = "ltc";

    // silently drop any problematic lines
    // TODO replace with a mode that flags problematic inputs and keeps statistics on them
    //
    // This distributes inputs on the fly to the parallel runners,
    // avoiding the need to load the initial input file completely into memory first
    BufReader::with_capacity(BUF_READER_CAPACITY, file)
        .lines()
        .par_bridge()
        .filter_map(|l| l.ok())
        .for_each(|passphrase| {
            // Count lines and print progress
            c.count_and_print_regularly();

            let effective_passphrase =
                adjust_passphrase_for_repetition(&passphrase, hasher_repetition_count);

            let entropy = compute_hashing(&hashtype, &effective_passphrase, hashing_rounds);

            let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&entropy[..]).unwrap();

            // Convert SecretKey to PrivateKey
            let privkey_compressed = PrivateKey {
                compressed: true,
                network: bitcoin::network::NetworkKind::Main,
                inner: secret_key,
            };

            let pubkey_compressed = privkey_compressed.public_key(secp);
            let pubkey_uncompressed = PublicKey::new_uncompressed(pubkey_compressed.inner);

            // manually construct the format from existing pubkey data
            let pubkey_compressed_secondformat = CompressedPublicKey {
                0: pubkey_compressed.inner,
            };

            // P2PKH with compressed pubkey
            let address_from_compressed_pubkey = p2pkh_manual_address_calculation(
                &pubkey_compressed.pubkey_hash(),
                LITECOIN_MAINNET_P2PKH_CONSTANT,
            );

            check_brainwallet_bloom_and_record_hits(
                &bloom,
                address_from_compressed_pubkey.to_string(),
                &wtr,
                source_id.to_string(),
                source_id2.to_string(),
                hashing_rounds.to_string(),
                coin_type.to_string(),
                "compressed".to_string(),
                "256".to_string(),
                effective_passphrase.to_string(),
                true,
            );

            // P2PKH with uncompressed pubkey
            let address_from_uncompressed_pubkey = p2pkh_manual_address_calculation(
                &pubkey_uncompressed.pubkey_hash(),
                LITECOIN_MAINNET_P2PKH_CONSTANT,
            );

            check_brainwallet_bloom_and_record_hits(
                &bloom,
                address_from_uncompressed_pubkey.to_string(),
                &wtr,
                source_id.to_string(),
                source_id2.to_string(),
                hashing_rounds.to_string(),
                coin_type.to_string(),
                "uncompressed".to_string(),
                "256".to_string(),
                effective_passphrase.to_string(),
                true,
            );

            // TODO search for P2SHWPKH addresses with the 0x05 byte (3-prefix)?
            // depends on the format of the bloom filter data source?

            // P2SHWPKH
            let address = p2shwpkh_manual_address_calculation(
                &pubkey_compressed_secondformat,
                LITECOIN_MAINNET_P2SH_CONSTANT,
            );

            check_brainwallet_bloom_and_record_hits(
                &bloom,
                address.to_string(),
                &wtr,
                source_id.to_string(),
                source_id2.to_string(),
                hashing_rounds.to_string(),
                coin_type.to_string(),
                "compressed".to_string(),
                "256".to_string(),
                effective_passphrase.to_string(),
                true,
            );

            // TODO harder to implement?

            // // P2WPKH is rare, but seen in the wild
            // let address = Address::p2wpkh(pubkey_compressed_secondformat, bitcoin_mainnet_constant)
            //     .to_string();

            // check_brainwallet_bloom_and_record_hits(
            //     &bloom,
            //     address.to_string(),
            //     &wtr,
            //     source_id.to_string(),
            //     source_id2.to_string(),
            //     hashing_rounds.to_string(),
            //     coin_type.to_string(),
            //     "compressed".to_string(),
            //     "256".to_string(),
            //     effective_passphrase.to_string(),
            //     true,
            // );

            // // experimentally check for basic P2TR format
            // // this is expected to be very rare
            // // calculating this address is fairly expensive
            // // TODO generalize hrp
            // let address = Address::p2tr(&secp, pubkey_compressed, None, bitcoin::KnownHrp::Mainnet)
            //     .to_string();
            // check_brainwallet_bloom_and_record_hits(
            //     &bloom,
            //     address.to_string(),
            //     &wtr,
            //     source_id.to_string(),
            //     source_id2.to_string(),
            //     hashing_rounds.to_string(),
            //     coin_type.to_string(),
            //     "compressed".to_string(),
            //     "256".to_string(),
            //     effective_passphrase.to_string(),
            //     true,
            // );
        });

    // ensure flush
    wtr.into_inner().unwrap().flush().unwrap();
}

pub fn brainwallet_sha256_check_eth(
    input_file: &String,
    output_file: &String,
    eth_bloom: &String,
    hashing_rounds: usize,
    hasher_repetition_count: usize,
    hashtype: Hashtype,
) {
    check_hashing_rounds_or_panic(hashing_rounds);
    let file = File::open(input_file).unwrap();
    let wtr = Mutex::new(csv::Writer::from_path(output_file).unwrap());

    let bloom = load_bloom_and_print_or_panic(eth_bloom);

    // log every 2^19 lines
    let c = Counter::new(0b0111_1111_1111_1111_1111);

    let secp = secp_engine();

    let source_id = get_hashtype_source_id(&hashtype);
    // silently drop any problematic lines
    // TODO replace with a mode that flags problematic inputs and keeps statistics on them
    //
    // This distributes inputs on the fly to the parallel runners,
    // avoiding the need to load the initial input file completely into memory first
    BufReader::with_capacity(BUF_READER_CAPACITY, file)
        .lines()
        .par_bridge()
        .filter_map(|l| l.ok())
        .for_each(|passphrase| {
            // Count lines and print progress
            c.count_and_print_regularly();

            let effective_passphrase =
                adjust_passphrase_for_repetition(&passphrase, hasher_repetition_count);

            let entropy = compute_hashing(&hashtype, &effective_passphrase, hashing_rounds);

            let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&entropy[..]).unwrap();

            let privkey_uncompressed = PrivateKey {
                compressed: false,
                network: bitcoin::network::NetworkKind::Main,
                inner: secret_key,
            };

            let pubkey_uncompressed = privkey_uncompressed.public_key(secp);
            let eth_address = get_eth_hex_address_from_pubkey_no_checksum(pubkey_uncompressed);

            check_brainwallet_bloom_and_record_hits(
                &bloom,
                eth_address.to_string(),
                &wtr,
                source_id.to_string(),
                "direct".to_string(),
                hashing_rounds.to_string(),
                "eth".to_string(),
                "uncompressed".to_string(),
                "256".to_string(),
                effective_passphrase.to_string(),
                true,
            );
        });

    // ensure flush
    wtr.into_inner().unwrap().flush().unwrap();
}
