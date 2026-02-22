use anyhow::{Context, Result};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::env;

pub struct BitcoinRpc {
    client: Client,
}

impl BitcoinRpc {
    pub fn new() -> Result<Self> {
        let host = env::var("BITCOIN_RPC_HOST").context("BITCOIN_RPC_HOST not set")?;
        let port = env::var("BITCOIN_RPC_PORT").context("BITCOIN_RPC_PORT not set")?;
        let user = env::var("BITCOIN_RPC_USER").context("BITCOIN_RPC_USER not set")?;
        let pass = env::var("BITCOIN_RPC_PASS").context("BITCOIN_RPC_PASS not set")?;

        let url = format!("http://{}:{}", host, port);
        let client = Client::new(&url, Auth::UserPass(user, pass))
            .context("Failed to create Bitcoin RPC client")?;

        Ok(Self { client })
    }

    pub fn get_blockchain_info(&self) -> Result<serde_json::Value> {
        self.client
            .call("getblockchaininfo", &[])
            .context("Failed to get blockchain info")
    }

    pub fn get_block_count(&self) -> Result<u64> {
        self.client
            .get_block_count()
            .context("Failed to get block count")
    }

    pub fn get_raw_transaction(&self, txid: &str) -> Result<serde_json::Value> {
        let txid_hash = txid
            .parse::<bitcoin::Txid>()
            .context("Invalid txid format")?;
        
        self.client
            .call("getrawtransaction", &[serde_json::to_value(txid_hash)?, serde_json::to_value(true)?])
            .context("Failed to get raw transaction")
    }
}
