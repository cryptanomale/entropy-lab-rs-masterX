#define BITCOIN_MAINNET 0
#define BITCOIN_TESTNET 1

typedef struct {
  bool compressed;
  int network;
  uchar key[32];
} private_key_t;

typedef struct {
  bool compressed;
  secp256k1_pubkey key;
} public_key_t;

typedef struct {
  uchar network;
  uchar depth;
  uchar parent_fingerprint[4];
  uint child_number;
  uchar chain_code[32];
  private_key_t private_key;
} extended_private_key_t;

typedef struct {
  uchar network;
  uchar depth;
  uchar parent_fingerprint[4];
  uint child_number;
  uchar chain_code[32];
  public_key_t public_key;
} extended_public_key_t;

void new_master_from_seed(uchar network, __private uchar *seed, __private extended_private_key_t * master) {
  uchar key[12] = { 0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64 };
  uchar hmacsha512_result[64] = { 0 };
  hmac_sha512(key, 12, seed, 64, hmacsha512_result);
  private_key_t pkey;
  pkey.compressed = false;
  pkey.network = network;
  memcpy_offset(&pkey.key, &hmacsha512_result, 0, 32);
  master->network = network;
  master->depth = 0;
  master->parent_fingerprint[0] = 0x00;
  master->parent_fingerprint[1] = 0x00;
  master->parent_fingerprint[2] = 0x00;
  master->parent_fingerprint[3] = 0x00;
  master->child_number = 0;
  master->private_key = pkey;
  memcpy_offset(&master->chain_code, &hmacsha512_result, 32, 32);
}

void public_from_private(__private extended_private_key_t *priv, __private extended_public_key_t *pub) {
  pub->network = priv->network;
  pub->depth = priv->depth;
  pub->child_number = priv->child_number;
  memcpy(&pub->parent_fingerprint,&priv->parent_fingerprint, 4);
  memcpy(&pub->chain_code, &priv->chain_code, 32);
  secp256k1_ec_pubkey_create(&pub->public_key.key, &priv->private_key.key);
}

void serialized_public_key(__private extended_public_key_t *pub, __private uchar *serialized_key) {
  secp256k1_ec_pubkey_serialize(serialized_key, 33, &pub->public_key.key, SECP256K1_EC_COMPRESSED);
}

void uncompressed_public_key(__private extended_public_key_t *pub, __private uchar *serialized_key) {
  secp256k1_ec_pubkey_serialize(serialized_key, 65, &pub->public_key.key, SECP256K1_EC_UNCOMPRESSED);
}

void identifier_for_public_key(__private extended_public_key_t *pub, __private uchar *identifier) {
  uchar serialized_key[33] = {0};
  serialized_public_key(pub, &serialized_key);
  { uchar sha256_result[32] __attribute__((aligned(4))) = {0}; sha256((__private uint*)serialized_key, 33, (__private uint*)sha256_result); ripemd160(sha256_result, 32, (__private uchar*)identifier); }
}

void fingerprint_for_public_key(__private extended_public_key_t *pub, __private uchar *fingerprint) {
  uchar identifier[20] = { 0 };
  identifier_for_public_key(pub, &identifier);
  fingerprint[0] = identifier[0];
  fingerprint[1] = identifier[1];
  fingerprint[2] = identifier[2];
  fingerprint[3] = identifier[3];
}

void p2shwpkh_address_for_public_key(__private extended_public_key_t *pub, __private uchar *address_bytes) {
  uchar pubkey_hash[20] = { 0 };
  identifier_for_public_key(pub, &pubkey_hash);

  uchar wpkh_script_bytes[22] = { 0 };
  wpkh_script_bytes[0] = 0x00;
  wpkh_script_bytes[1] = 0x14;
  for(int i=0;i<20;i++){
    wpkh_script_bytes[i+2] = pubkey_hash[i];
  }

  uchar wpkh_script_hash[20] = { 0 };
  { uchar sha256_result[32] __attribute__((aligned(4))) = {0}; sha256((__private uint*)wpkh_script_bytes, 22, (__private uint*)sha256_result); ripemd160(sha256_result, 32, (__private uchar*)wpkh_script_hash); }

  address_bytes[0] = 5;

  for(int i=0;i<20;i++) {
    address_bytes[i+1] = wpkh_script_hash[i];
  }
  
  uchar sha256d_result[32] = { 0 };
  { uchar temp[32] __attribute__((aligned(4))); sha256((__private uint*)address_bytes, 21, (__private uint*)temp); sha256((__private uint*)temp, 32, (__private uint*)sha256d_result); }

  address_bytes[21] = sha256d_result[0];
  address_bytes[22] = sha256d_result[1];
  address_bytes[23] = sha256d_result[2];
  address_bytes[24] = sha256d_result[3];
}

void normal_private_child_from_private(__private extended_private_key_t *parent, __private extended_private_key_t *child, uint normal_child_number) {
  uchar hmacsha512_result[64] = { 0 };
  extended_public_key_t pub;
  public_from_private(parent, &pub);
  uchar hmac_input[37] = {0};
  serialized_public_key(&pub, &hmac_input);
  hmac_input[33] = normal_child_number >> 24;
  hmac_input[34] = (normal_child_number & 0x00FF0000) >> 16;
  hmac_input[35] = (normal_child_number & 0x0000FF00) >> 8;
  hmac_input[36] = (normal_child_number & 0x000000FF);
  hmac_sha512(parent->chain_code, 32, hmac_input, 37, hmacsha512_result);

  private_key_t sk;
  sk.compressed = true;
  sk.network = parent->network;
  memcpy(&sk.key, &hmacsha512_result, 32);
  secp256k1_ec_seckey_tweak_add(&sk.key, &parent->private_key.key);
  child->network = parent->network;
  child->depth = parent->depth + 1;
  child->child_number = normal_child_number;
  child->private_key = sk;
  memcpy_offset(child->chain_code, hmacsha512_result, 32, 32);
}

static void p2pkh_address_for_public_key(__private extended_public_key_t *pub, __private uchar *address_bytes) {
  uchar pubkey_hash[20] = { 0 };
  identifier_for_public_key(pub, &pubkey_hash);

  address_bytes[0] = 0;
  for(int i=0;i<20;i++){
    address_bytes[i+1] = pubkey_hash[i];
  }

  uchar sha256d_result[64] = { 0 };
  { uchar temp[32] __attribute__((aligned(4))); sha256((__private uint*)address_bytes, 21, (__private uint*)temp); sha256((__private uint*)temp, 32, (__private uint*)sha256d_result); }

  address_bytes[21] = sha256d_result[0];
  address_bytes[22] = sha256d_result[1];
  address_bytes[23] = sha256d_result[2];
  address_bytes[24] = sha256d_result[3];
}

static void bech32_address_for_public_key(__private extended_public_key_t *pub, __private uchar *address_bytes) {
    identifier_for_public_key(pub, address_bytes);
}

void address_for_public_key(__private extended_public_key_t *pub, uint purpose, __private uchar *address_bytes) {
  if (purpose == 44) {
    p2pkh_address_for_public_key(pub, address_bytes);
  } else if (purpose == 49) {
    p2shwpkh_address_for_public_key(pub, address_bytes);
  } else if (purpose == 84) {
    bech32_address_for_public_key(pub, address_bytes);
  }
}

void hardened_private_child_from_private(__private extended_private_key_t *parent, __private extended_private_key_t *child, uint hardened_child_number) {

  uint child_number = (1 << 31) + hardened_child_number;
  uchar hmacsha512_result[64] = { 0 };
  uchar hmac_input[37] = {0};
  for(int x=0;x<32;x++){
    hmac_input[x+1] = parent->private_key.key[x];
  }
  hmac_input[33] = child_number >> 24;
  hmac_input[34] = (child_number & 0x00FF0000) >> 16;
  hmac_input[35] = (child_number & 0x0000FF00) >> 8;
  hmac_input[36] = (child_number & 0x000000FF);
  
  hmac_sha512(parent->chain_code, 32, hmac_input, 37, hmacsha512_result);
  
  private_key_t sk;
  sk.compressed = true;
  sk.network = parent->network;
  memcpy(&sk.key, &hmacsha512_result, 32);
  secp256k1_ec_seckey_tweak_add(&sk.key, &parent->private_key.key);
  child->network = parent->network;
  child->depth = parent->depth + 1;
  child->child_number = child_number;
  child->private_key = sk;
  memcpy_offset(child->chain_code, hmacsha512_result, 32, 32);
}

// ---------------------------------------------------------------------------
// Taproot (BIP-340 / BIP-86) helpers
//
// tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
//
// Pre-computed SHA256("TapTweak") (32 bytes, big-endian):
//   e80fe1639c9ca050e3af1b39c143c63e429cbceb15d940fbb5c5a2f4af59347d
// ---------------------------------------------------------------------------
static void taptweak_tagged_hash(__private const uchar x_only[32],
                                 __private uchar out[32])
{
    // SHA256("TapTweak") -- constant, pre-computed
    // "TapTweak" = 0x54617054776561k (8 bytes)
    // hash = e80fe1639c9ca050e3af1b39c143c63e429cbceb15d940fbb5c5a2f4af59347d
    __private uchar tag_hash[32] = {
        0xe8, 0x0f, 0xe1, 0x63, 0x9c, 0x9c, 0xa0, 0x50,
        0xe3, 0xaf, 0x1b, 0x39, 0xc1, 0x43, 0xc6, 0x3e,
        0x42, 0x9c, 0xbc, 0xeb, 0x15, 0xd9, 0x40, 0xfb,
        0xb5, 0xc5, 0xa2, 0xf4, 0xaf, 0x59, 0x34, 0x7d
    };

    // Build input: tag_hash || tag_hash || x_only  (96 bytes)
    uchar buf[96];
    for (int i = 0; i < 32; i++) buf[i]      = tag_hash[i];
    for (int i = 0; i < 32; i++) buf[i + 32] = tag_hash[i];
    for (int i = 0; i < 32; i++) buf[i + 64] = x_only[i];

    uchar result[32] __attribute__((aligned(4)));
    sha256((__private uint*)buf, 96, (__private uint*)result);
    for (int i = 0; i < 32; i++) out[i] = result[i];
}

// Compute Taproot x-only tweaked pubkey identifier (HASH160 of 32-byte x).
// Method:
//   1. Serialize compressed pubkey, extract x_only = bytes[1..33]
//   2. tweak = tagged_hash("TapTweak", x_only)   [32 bytes]
//   3. tweaked_privkey = privkey + tweak  (scalar mod n)
//      -- we work on the private key side to avoid a full EC add on GPU
//   4. tweaked_pubkey = tweaked_privkey * G  -> serialize -> x_only_tweaked
//   5. identifier[0..20] = HASH160(x_only_tweaked)
void taproot_identifier(__private extended_private_key_t *priv,
                        __private uchar identifier[20])
{
    // Step 1: get x-only pubkey from internal pubkey
    extended_public_key_t pub;
    public_from_private(priv, &pub);
    uchar compressed[33];
    serialized_public_key(&pub, compressed);
    uchar x_only[32];
    for (int i = 0; i < 32; i++) x_only[i] = compressed[i + 1];

    // Step 2: tagged hash (TapTweak)
    uchar tweak[32];
    taptweak_tagged_hash(x_only, tweak);

    // Step 3: tweaked privkey = privkey + tweak  (mod n, via secp256k1_ec_seckey_tweak_add)
    uchar tweaked_privkey[32];
    for (int i = 0; i < 32; i++) tweaked_privkey[i] = priv->private_key.key[i];
    secp256k1_ec_seckey_tweak_add(tweaked_privkey, tweak);

    // Step 4: tweaked pubkey -> x-only
    secp256k1_pubkey tweaked_pub;
    secp256k1_ec_pubkey_create(&tweaked_pub, tweaked_privkey);
    uchar tweaked_compressed[33];
    secp256k1_ec_pubkey_serialize(tweaked_compressed, 33, &tweaked_pub, SECP256K1_EC_COMPRESSED);
    uchar x_tweaked[32];
    for (int i = 0; i < 32; i++) x_tweaked[i] = tweaked_compressed[i + 1];

    // Step 5: HASH160(x_only_tweaked)
    uchar sha256_result[32] __attribute__((aligned(4)));
    sha256((__private uint*)x_tweaked, 32, (__private uint*)sha256_result);
    ripemd160(sha256_result, 32, identifier);
}
