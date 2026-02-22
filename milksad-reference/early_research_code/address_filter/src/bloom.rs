use bloomfilter::Bloom;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Load custom serialization format with wrapped bloomfilter 1.x bit data.
///
/// This is deprecated and should not be used for new projects.
///
/// Security notice: header fields get used without checks, only use on trusted inputs
pub fn load(file: &Path) -> Result<Bloom<String>, Box<dyn Error>> {
    let file = File::open(file)?;
    let length = file.metadata().unwrap().len();

    let mut buf = BufReader::new(file);

    let mut num_bits: [u8; 8] = [0; 8];
    buf.read_exact(&mut num_bits)?;

    let mut num_hash_fun: [u8; 4] = [0; 4];
    buf.read_exact(&mut num_hash_fun)?;

    let mut sk00: [u8; 8] = [0; 8];
    buf.read_exact(&mut sk00)?;
    let mut sk01: [u8; 8] = [0; 8];
    buf.read_exact(&mut sk01)?;
    let mut sk10: [u8; 8] = [0; 8];
    buf.read_exact(&mut sk10)?;
    let mut sk11: [u8; 8] = [0; 8];
    buf.read_exact(&mut sk11)?;

    let number_of_bits: u64 = u64::from_be_bytes(num_bits);
    let number_of_hash_functions: u32 = u32::from_be_bytes(num_hash_fun);
    let sip_keys: [(u64, u64); 2] = [
        (u64::from_be_bytes(sk00), (u64::from_be_bytes(sk01))),
        (u64::from_be_bytes(sk10), (u64::from_be_bytes(sk11))),
    ];

    let mut bitmap = vec![0; (length - 8 - 4 - 32) as usize];
    buf.read_exact(&mut bitmap)?;

    Ok(Bloom::from_existing(
        &bitmap,
        number_of_bits,
        number_of_hash_functions,
        sip_keys,
    ))
}
