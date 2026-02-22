#include <algorithm>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "bip39_dictionary.hpp"
#include "sha256.h"

// PoC author: Christian Reitter
// Note: experimental code
// See local notes and the README for more license and authorship information
// Unless noted otherwise, licensed AGPLv3 or later

// stay close to libbitcoin in type description
typedef std::vector<uint8_t> data_chunk;

// function adapted from
// https://stackoverflow.com/questions/26503606/better-way-to-convert-a-vector-of-uint8-to-an-ascii-hexadecimal-string
// Licensed under CC BY-SA 3.0
// Author https://stackoverflow.com/users/596781/kerrek-sb
std::string uint8_vector_to_hex_string(const std::vector<uint8_t> &v) {
  std::string result;
  result.reserve(v.size() * 2); // two digits per character

  // adapted to lowercase hex
  static constexpr char hex[] = "0123456789abcdef";

  for (uint8_t c : v) {
    result.push_back(hex[c / 16]);
    result.push_back(hex[c % 16]);
  }

  return result;
}

// sha256 specific container, fixed size
typedef std::array<uint8_t, 32> hash_digest_sha256;

hash_digest_sha256 sha256_hash(data_chunk data) {
  hash_digest_sha256 hash;
  SHA256_(data.data(), data.size(), hash.data());
  return hash;
}

// BIP-39 private constants.
static constexpr size_t bits_per_word = 11;
static constexpr size_t entropy_bit_divisor = 32;
constexpr uint8_t byte_bits = 8;
static constexpr size_t mnemonic_seed_multiple = 4;

// Represents a mnemonic word list.
typedef std::vector<std::string> string_list;
typedef string_list word_list;

// function taken from
// https://stackoverflow.com/questions/5288396/c-ostream-out-manipulation/5289170#5289170
// License should be CC BY-SA 4.0 (edited after 2018-05-02)
// Author https://stackoverflow.com/users/85371/sehe
//
// note: delimiter cannot contain NUL characters
template <typename Range, typename Value = typename Range::value_type>
std::string Join(Range const &elements, const char *const delimiter) {
  std::ostringstream os;
  auto b = begin(elements), e = end(elements);

  if (b != e) {
    std::copy(b, prev(e), std::ostream_iterator<Value>(os, delimiter));
    b = prev(e);
  }
  if (b != e) {
    os << *b;
  }

  return os.str();
}

inline uint8_t bip39_shift(size_t bit) {
  return (1 << (byte_bits - (bit % byte_bits) - 1));
}

word_list create_mnemonic(data_chunk entropy, const dictionary &lexicon) {
  if ((entropy.size() % mnemonic_seed_multiple) != 0)
    return word_list();

  const size_t entropy_bits = (entropy.size() * 8);
  const size_t check_bits = (entropy_bits / entropy_bit_divisor);
  const size_t total_bits = (entropy_bits + check_bits);
  const size_t word_count = (total_bits / bits_per_word);

  // disabled assert
  // BITCOIN_ASSERT((total_bits % bits_per_word) == 0);
  // BITCOIN_ASSERT((word_count % mnemonic_word_multiple) == 0);

  // old code for reference:
  // const auto data = build_chunk({entropy, sha256_hash(entropy)});

  // this does the chunk building without a detour over other libbitcoin types
  auto data = entropy;
  auto checksum_bytes = sha256_hash(entropy);
  // mechanism based on
  // https://stackoverflow.com/questions/259297/how-do-you-copy-the-contents-of-an-array-to-a-stdvector-in-c-without-looping
  // CC BY-SA 2.5, author https://stackoverflow.com/users/7405/mattyt
  // uint8_t array, omit the /1 division since sizeof(uint8_t) == 1 byte
  data.insert(data.end(), &checksum_bytes[0],
              &checksum_bytes[checksum_bytes.size()]);

  size_t bit = 0;
  word_list words;

  for (size_t word = 0; word < word_count; word++) {
    size_t position = 0;
    for (size_t loop = 0; loop < bits_per_word; loop++) {
      bit = (word * bits_per_word + loop);
      position <<= 1;

      const auto byte = bit / 8;

      if ((data[byte] & bip39_shift(bit)) > 0)
        position++;
    }

    // disabled assert
    // BITCOIN_ASSERT(position < dictionary_size);
    words.push_back(lexicon[position]);
  }

  // disabled assert
  // BITCOIN_ASSERT(words.size() == ((bit + 1) / bits_per_word));
  return words;
}

void main_wallet_generation_loop(size_t bit_length,
                                 uint32_t rng_target_index_start,
                                 uint32_t rng_target_index_end) {

  uint32_t rng_target_index = rng_target_index_start;

  // the distribution is static
  std::uniform_int_distribution<uint16_t> distribution(0, 255);
  // this gets re-used during computation, initialized with 0 as dummy
  std::mt19937 twister(0);

  // as defined in libbitcoin
  size_t fill_seed_size = bit_length / 8;
  data_chunk seed(fill_seed_size);

  // hot loop
  while (true) {
    // simulate the `bx seed` output for the index in question
    // one index step represents one nanosecond in the time based PRNG seeding

    // Context: former pseudo_random_fill() start
    twister.seed(rng_target_index);

    const auto fill = [&distribution, &twister](uint8_t byte) {
      return static_cast<uint8_t>((distribution)(twister));
    };

    std::transform(seed.begin(), seed.end(), seed.begin(), fill);
    // Context: former pseudo_random_fill() end

    // weak "entropy" data used by BIP39
    // print basic index,entropy CSV to stdout
    // std::cout << rng_target_index << "," << uint8_vector_to_hex_string(seed)
    // << "\n";

    // Optimization potential, the Join() is likely too expensive
    // print basic CSV to stdout:
    // index,bip39 mnemonic (with spaces)
    std::cout << rng_target_index << "," << Join(create_mnemonic(seed, en), " ")
              << "\n";

    // stop looping if we've hit the goal
    // reminder: be careful with unsigned integer overflow
    if (rng_target_index >= rng_target_index_end) {
      break;
    }
    rng_target_index++;
  }
}

int main() {
// Note hardcoded English BIP39 wordlist choice
// other BIP39 wordlist languages require code changes

// context:
// size_t bit_length = 128; // lowest allowed
// size_t bit_length = 192; // bx seed default on 3.2.0
// other bit lengths possible but unusual
#ifndef BIT_LENGTH
#define BIT_LENGTH 256
#endif

// minimum value 0
#ifndef RNG_TARGET_INDEX_START
#define RNG_TARGET_INDEX_START 0
#endif

// maximum value 4294967295
#ifndef RNG_TARGET_INDEX_END
#define RNG_TARGET_INDEX_END 4294967295
#endif

  size_t bit_length = BIT_LENGTH;
  uint32_t rng_target_index_start = RNG_TARGET_INDEX_START;
  uint32_t rng_target_index_end = RNG_TARGET_INDEX_END;

  // print stderr to avoid tainting the main output
  std::cerr << " Running generation with the following parameters: \n";
  std::cerr << " bit_length " << bit_length << "\n";
  std::cerr << " rng_target_index_start " << rng_target_index_start << "\n";
  std::cerr << " rng_target_index_end " << rng_target_index_end << "\n";

  main_wallet_generation_loop(bit_length, rng_target_index_start,
                              rng_target_index_end);

  return 0;
}