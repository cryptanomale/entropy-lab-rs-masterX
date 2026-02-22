// All dependencies loaded by gpu_solver.rs before this file
// No need for #include directives

// OPTIMIZATION: Use __global const restrict for read-only buffers to enable better caching
// OPTIMIZATION: Memory coalescing achieved by sequential thread access pattern
__kernel void batch_address(
    __global const ulong * restrict entropies_hi, 
    __global const ulong * restrict entropies_lo, 
    __global uchar * restrict output_addresses, 
    uint purpose,
    uint batch_size
) {
  ulong idx = get_global_id(0);
  if (idx >= batch_size) return;
  
  // OPTIMIZATION: Coalesced memory reads - threads access consecutive elements
  ulong mnemonic_hi = entropies_hi[idx];
  ulong mnemonic_lo = entropies_lo[idx];

  // --- Mnemonic Generation (from int_to_address.cl) ---
  // OPTIMIZATION: Aligned buffers for better memory access
  uchar bytes[16] __attribute__((aligned(16)));
  bytes[15] = mnemonic_lo & 0xFF;
  bytes[14] = (mnemonic_lo >> 8) & 0xFF;
  bytes[13] = (mnemonic_lo >> 16) & 0xFF;
  bytes[12] = (mnemonic_lo >> 24) & 0xFF;
  bytes[11] = (mnemonic_lo >> 32) & 0xFF;
  bytes[10] = (mnemonic_lo >> 40) & 0xFF;
  bytes[9] = (mnemonic_lo >> 48) & 0xFF;
  bytes[8] = (mnemonic_lo >> 56) & 0xFF;
  
  bytes[7] = mnemonic_hi & 0xFF;
  bytes[6] = (mnemonic_hi >> 8) & 0xFF;
  bytes[5] = (mnemonic_hi >> 16) & 0xFF;
  bytes[4] = (mnemonic_hi >> 24) & 0xFF;
  bytes[3] = (mnemonic_hi >> 32) & 0xFF;
  bytes[2] = (mnemonic_hi >> 40) & 0xFF;
  bytes[1] = (mnemonic_hi >> 48) & 0xFF;
  bytes[0] = (mnemonic_hi >> 56) & 0xFF;

  uchar mnemonic_hash[32] __attribute__((aligned(4)));
  sha256((__private const uint*)bytes, 16, (__private uint*)mnemonic_hash);
  uchar checksum = (mnemonic_hash[0] >> 4) & ((1 << 4)-1);
  ushort indices[12];
  indices[0] = (mnemonic_hi >> 53) & 2047;
  indices[1] = (mnemonic_hi >> 42) & 2047;
  indices[2] = (mnemonic_hi >> 31) & 2047;
  indices[3] = (mnemonic_hi >> 20) & 2047;
  indices[4] = (mnemonic_hi >> 9)  & 2047;
  indices[5] = ((mnemonic_hi & ((1 << 9)-1)) << 2) | ((mnemonic_lo >> 62) & 3);
  indices[6] = (mnemonic_lo >> 51) & 2047;
  indices[7] = (mnemonic_lo >> 40) & 2047;
  indices[8] = (mnemonic_lo >> 29) & 2047;
  indices[9] = (mnemonic_lo >> 18) & 2047;
  indices[10] = (mnemonic_lo >> 7) & 2047;
  indices[11] = ((mnemonic_lo & ((1 << 7)-1)) << 4) | checksum;

  uchar mnemonic[180] = {0};
  uchar mnemonic_length = 11 + word_lengths[indices[0]] + word_lengths[indices[1]] + word_lengths[indices[2]] + word_lengths[indices[3]] + word_lengths[indices[4]] + word_lengths[indices[5]] + word_lengths[indices[6]] + word_lengths[indices[7]] + word_lengths[indices[8]] + word_lengths[indices[9]] + word_lengths[indices[10]] + word_lengths[indices[11]];
  int mnemonic_index = 0;
  
  for (int i=0; i < 12; i++) {
    int word_index = indices[i];
    int word_length = word_lengths[word_index];
    
    for(int j=0;j<word_length;j++) {
      mnemonic[mnemonic_index] = words[word_index][j];
      mnemonic_index++;
    }
    mnemonic[mnemonic_index] = 32;
    mnemonic_index++;
  }
  mnemonic[mnemonic_index - 1] = 0;

  // --- PBKDF2 (Mnemonic -> Seed) ---
  uchar seed[64] __attribute__((aligned(4)));
  uchar salt[12] = { 109, 110, 101, 109, 111, 110, 105, 99, 0, 0, 0, 1 }; // "mnemonic" + 1
  
  if (purpose == 0) {
      // Cake Wallet Electrum salt
      salt[0] = 101; salt[1] = 108; salt[2] = 101; salt[3] = 99;
      salt[4] = 116; salt[5] = 114; salt[6] = 117; salt[7] = 109;
  }

  mnemonic_to_seed(mnemonic, mnemonic_length, salt, 12, seed);

  // --- Address Derivation ---
  uchar network = BITCOIN_MAINNET;
  extended_private_key_t master_private;
  
  new_master_from_seed(network, seed, &master_private);

  extended_private_key_t target_key;
  extended_public_key_t target_public_key;
  
  if (purpose == 0) {
      // Cake Wallet: m/0'/0/0 (special case)
      hardened_private_child_from_private(&master_private, &target_key, 0);
      normal_private_child_from_private(&target_key, &target_key, 0);
      normal_private_child_from_private(&target_key, &target_key, 0);
  } else {
      // Standard BIP paths: m / purpose' / 0' / 0' / 0 / 0
      hardened_private_child_from_private(&master_private, &target_key, purpose);
      hardened_private_child_from_private(&target_key, &target_key, 0);
      hardened_private_child_from_private(&target_key, &target_key, 0);
      normal_private_child_from_private(&target_key, &target_key, 0);
      normal_private_child_from_private(&target_key, &target_key, 0);
  }
  public_from_private(&target_key, &target_public_key);

  uchar raw_address[25] = {0};

  if (purpose == 0) {
      // Cake Wallet: P2PKH (Legacy 1...)
      uchar sha256_result[32] __attribute__((aligned(4)));
      uchar ripemd160_result[20];
      uchar serialized_pubkey[33] __attribute__((aligned(4)));
      serialized_public_key(&target_public_key, serialized_pubkey);
      
      sha256((__private const uint*)serialized_pubkey, 33, (__private uint*)sha256_result);
      ripemd160(sha256_result, 32, ripemd160_result);
      
      raw_address[0] = 0x00; // Mainnet
      for(int i=0; i<20; i++) raw_address[i+1] = ripemd160_result[i];
      
      // Checksum
      uchar raw_address_aligned[32] __attribute__((aligned(4)));
      for(int i=0; i<21; i++) raw_address_aligned[i] = raw_address[i];
      
      sha256((__private const uint*)raw_address_aligned, 21, (__private uint*)sha256_result);
      sha256((__private const uint*)sha256_result, 32, (__private uint*)sha256_result);
      
      raw_address[21] = sha256_result[0];
      raw_address[22] = sha256_result[1];
      raw_address[23] = sha256_result[2];
      raw_address[24] = sha256_result[3];
  } else if (purpose == 100) {
      // Milk Sad (Libbitcoin): MT19937 seeded with timestamp
      // Input: entropies_hi[idx] contains the timestamp (cast to uint)
      uint timestamp = (uint)entropies_hi[idx];
      
      uint mt_output[4];
      mt19937_extract_128(timestamp, mt_output);
      
      // Convert 4 uints to 16 bytes entropy
      // MT19937 outputs are little-endian or big-endian? 
      // std::mt19937 produces native u32. We treat them as bytes.
      // We need to match how `bx seed` does it.
      // `bx seed` prints hex.
      // If we treat the 4 words as a byte array, that's our entropy.
      
      uchar entropy[16];
      // Word 0
      entropy[0] = (mt_output[0] >> 24) & 0xFF;
      entropy[1] = (mt_output[0] >> 16) & 0xFF;
      entropy[2] = (mt_output[0] >> 8) & 0xFF;
      entropy[3] = (mt_output[0]) & 0xFF;
      // Word 1
      entropy[4] = (mt_output[1] >> 24) & 0xFF;
      entropy[5] = (mt_output[1] >> 16) & 0xFF;
      entropy[6] = (mt_output[1] >> 8) & 0xFF;
      entropy[7] = (mt_output[1]) & 0xFF;
      // Word 2
      entropy[8] = (mt_output[2] >> 24) & 0xFF;
      entropy[9] = (mt_output[2] >> 16) & 0xFF;
      entropy[10] = (mt_output[2] >> 8) & 0xFF;
      entropy[11] = (mt_output[2]) & 0xFF;
      // Word 3
      entropy[12] = (mt_output[3] >> 24) & 0xFF;
      entropy[13] = (mt_output[3] >> 16) & 0xFF;
      entropy[14] = (mt_output[3] >> 8) & 0xFF;
      entropy[15] = (mt_output[3]) & 0xFF;
      
      // BIP39 Mnemonic
      uchar mnemonic[256]; // Buffer for mnemonic string
      int mnemonic_len = generate_mnemonic(entropy, 16, mnemonic);
      
      // BIP39 Seed
      uchar seed[64];
      uchar salt[12] = { 109, 110, 101, 109, 111, 110, 105, 99, 0, 0, 0, 1 };
      mnemonic_to_seed(mnemonic, mnemonic_len, salt, 12, seed);
      
      // BIP32 Derivation m/44'/0'/0'/0/0
      extended_private_key_t master_private;
      new_master_from_seed(BITCOIN_MAINNET, seed, &master_private);
      
      extended_private_key_t target_key;
      hardened_private_child_from_private(&master_private, &target_key, 44);
      hardened_private_child_from_private(&target_key, &target_key, 0);
      hardened_private_child_from_private(&target_key, &target_key, 0);
      normal_private_child_from_private(&target_key, &target_key, 0);
      normal_private_child_from_private(&target_key, &target_key, 0);
      
      // P2PKH Address (Legacy)
      uchar sha256_result[32] __attribute__((aligned(4)));
      uchar ripemd160_result[20];
      uchar serialized_pubkey[33] __attribute__((aligned(4)));
      
      public_key_t pub_key;
      secp256k1_ec_pubkey_create(&pub_key, (const __private unsigned char*)&target_key.private_key);
      serialized_public_key(&pub_key, serialized_pubkey);
      
      sha256((__private const uint*)serialized_pubkey, 33, (__private uint*)sha256_result);
      ripemd160(sha256_result, 32, ripemd160_result);
      
      raw_address[0] = 0x00; // Mainnet
      for(int i=0; i<20; i++) raw_address[i+1] = ripemd160_result[i];
      
      // Checksum
      uchar raw_address_aligned[32] __attribute__((aligned(4)));
      for(int i=0; i<21; i++) raw_address_aligned[i] = raw_address[i];
      
      sha256((__private const uint*)raw_address_aligned, 21, (__private uint*)sha256_result);
      sha256((__private const uint*)sha256_result, 32, (__private uint*)sha256_result);
      
      raw_address[21] = sha256_result[0];
      raw_address[22] = sha256_result[1];
      raw_address[23] = sha256_result[2];
      raw_address[24] = sha256_result[3];
      
  } else if (purpose == 200) {
      // Cake Wallet Dart PRNG (time-based)
      // Input: entropies_hi[idx] contains timestamp in microseconds
      ulong timestamp_us = entropies_hi[idx];
      
      // Initialize Dart Random with timestamp
      DartRandom dart_rng;
      dart_random_init(&dart_rng, timestamp_us);
      
      // Generate 16 bytes entropy
      uchar entropy[16];
      dart_random_generate_bytes(&dart_rng, entropy, 16);
      
      // BIP39 Mnemonic
      uchar mnemonic[256];
      int mnemonic_len = generate_mnemonic(entropy, 16, mnemonic);
      
      // BIP39 Seed
      uchar seed[64];
      uchar salt[12] = { 109, 110, 101, 109, 111, 110, 105, 99, 0, 0, 0, 1 };
      mnemonic_to_seed(mnemonic, mnemonic_len, salt, 12, seed);
      
      // BIP32 Derivation m/0'/0/0 (Cake Wallet path)
      extended_private_key_t master_private;
      new_master_from_seed(BITCOIN_MAINNET, seed, &master_private);
      
      extended_private_key_t target_key;
      hardened_private_child_from_private(&master_private, &target_key, 0);
      normal_private_child_from_private(&target_key, &target_key, 0);
      normal_private_child_from_private(&target_key, &target_key, 0);
      
      // P2PKH Address (Legacy)
      uchar sha256_result[32] __attribute__((aligned(4)));
      uchar ripemd160_result[20];
      uchar serialized_pubkey[33] __attribute__((aligned(4)));
      
      public_key_t pub_key;
      secp256k1_ec_pubkey_create(&pub_key, (const __private unsigned char*)&target_key.private_key);
      serialized_public_key(&pub_key, serialized_pubkey);
      
      sha256((__private const uint*)serialized_pubkey, 33, (__private uint*)sha256_result);
      ripemd160(sha256_result, 32, ripemd160_result);
      
      raw_address[0] = 0x00; // Mainnet
      for(int i=0; i<20; i++) raw_address[i+1] = ripemd160_result[i];
      
      // Checksum
      uchar raw_address_aligned[32] __attribute__((aligned(4)));
      for(int i=0; i<21; i++) raw_address_aligned[i] = raw_address[i];
      
      sha256((__private const uint*)raw_address_aligned, 21, (__private uint*)sha256_result);
      sha256((__private const uint*)sha256_result, 32, (__private uint*)sha256_result);
      
      raw_address[21] = sha256_result[0];
      raw_address[22] = sha256_result[1];
      raw_address[23] = sha256_result[2];
      raw_address[24] = sha256_result[3];
      
  } else if (purpose == 49) {
      // P2SH-WPKH (BIP49)
      p2shwpkh_address_for_public_key(&target_public_key, raw_address);
  } else if (purpose == 44) {
      // P2PKH (Legacy BIP44)
      uchar sha256_result[32] __attribute__((aligned(4)));
      uchar ripemd160_result[20];
      uchar serialized_pubkey[33] __attribute__((aligned(4)));
      serialized_public_key(&target_public_key, serialized_pubkey);
      
      sha256((__private const uint*)serialized_pubkey, 33, (__private uint*)sha256_result);
      ripemd160(sha256_result, 32, ripemd160_result);
      
      raw_address[0] = 0x00; // Mainnet
      for(int i=0; i<20; i++) raw_address[i+1] = ripemd160_result[i];
      
      // Checksum needs sha256
      uchar raw_address_aligned[32] __attribute__((aligned(4))); // Copy to aligned buffer
      for(int i=0; i<21; i++) raw_address_aligned[i] = raw_address[i];
      
      sha256((__private const uint*)raw_address_aligned, 21, (__private uint*)sha256_result);
      sha256((__private const uint*)sha256_result, 32, (__private uint*)sha256_result);
      
      raw_address[21] = sha256_result[0];
      raw_address[22] = sha256_result[1];
      raw_address[23] = sha256_result[2];
      raw_address[24] = sha256_result[3];
  } else if (purpose == 84) {
      // P2WPKH (Native SegWit BIP84)
      uchar sha256_result[32] __attribute__((aligned(4)));
      uchar ripemd160_result[20];
      uchar serialized_pubkey[33] __attribute__((aligned(4)));
      serialized_public_key(&target_public_key, serialized_pubkey);
      
      sha256((__private const uint*)serialized_pubkey, 33, (__private uint*)sha256_result);
      ripemd160(sha256_result, 32, ripemd160_result);
      
      for(int i=0; i<20; i++) raw_address[i] = ripemd160_result[i];
  }

  // OPTIMIZATION: Coalesced memory writes - sequential pattern for best performance
  // Write output in chunks to maximize memory bandwidth
  __global uchar* out_ptr = output_addresses + (idx * 25);
  
  #pragma unroll
  for(int i=0; i<25; i++) {
      out_ptr[i] = raw_address[i];
  }
}
