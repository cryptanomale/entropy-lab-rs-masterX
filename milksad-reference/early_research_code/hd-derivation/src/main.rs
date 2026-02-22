extern crate bitcoin;
extern crate bs58;
extern crate structopt;

use bitcoin::Network;
use bitcoin::util::address::Address;
use bitcoin::util::bip32::{XPriv, DerivationPath};
use bitcoin::util::key::PublicKey;
use bitcoin::secp256k1::Secp256k1;
use std::str::FromStr;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "hdd", about = "An HD derivation tool.")]
pub struct Opt {
    #[structopt(short = "x", long = "xpriv")]
    pub xpriv: String,

    #[structopt(short = "p", long = "path")]
    pub path: String,
}

pub fn derive_child_address(xpriv: &str, path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let decoded_xpriv = XPriv::from_str(xpriv)?;
    let child_path = DerivationPath::from_str(path)?;
    let child_key = decoded_xpriv.derive_priv(&secp, &child_path)?;
    let public_key = PublicKey::from_private_key(&secp, &child_key.private_key);
    let address = Address::p2pkh(&public_key, Network::Bitcoin);
    Ok(address.to_string())
}

fn main() {
    let opt = Opt::from_args();
    match derive_child_address(&opt.xpriv, &opt.path) {
        Ok(address) => println!("Derived address: {}", address),
        Err(e) => println!("Error: {}", e),
    }
}
