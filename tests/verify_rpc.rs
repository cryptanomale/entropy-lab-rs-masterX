use temporal_planetarium_lib::utils::bitcoin_rpc::BitcoinRpc;
use dotenv::dotenv;

#[test]
#[ignore] // Requires active Bitcoin node from user details
fn test_verify_bitcoin_rpc_connection() {
    dotenv().ok();
    
    let rpc = BitcoinRpc::new().expect("Failed to initialize RPC client from .env");
    let info = rpc.get_blockchain_info().expect("Failed to get blockchain info");
    
    println!("SUCCESS: Connected to Bitcoin RPC!");
    println!("Blockchain Info: {}", serde_json::to_string_pretty(&info).unwrap());
    
    let block_count = rpc.get_block_count().expect("Failed to get block count");
    println!("Current Block Count: {}", block_count);
    
    assert!(block_count > 0, "Block count should be greater than 0");
}
