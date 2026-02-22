all: bx_seed_walker_bip39_mnemonic_128bit bx_seed_walker_bip39_mnemonic_192bit bx_seed_walker_bip39_mnemonic_256bit

bx_seed_walker_bip39_mnemonic_128bit: bx_seed_walker_bip39_mnemonic.cpp sha256.c sha256.h bip39_dictionary.hpp
	g++ -std=c++11 bx_seed_walker_bip39_mnemonic.cpp sha256.c -O3 -march=native -DBIT_LENGTH=128 -o bx_seed_walker_bip39_mnemonic_128bit

bx_seed_walker_bip39_mnemonic_192bit: bx_seed_walker_bip39_mnemonic.cpp sha256.c sha256.h bip39_dictionary.hpp
	g++ -std=c++11 bx_seed_walker_bip39_mnemonic.cpp sha256.c -O3 -march=native -DBIT_LENGTH=192 -o bx_seed_walker_bip39_mnemonic_192bit

bx_seed_walker_bip39_mnemonic_256bit: bx_seed_walker_bip39_mnemonic.cpp sha256.c sha256.h bip39_dictionary.hpp
	g++ -std=c++11 bx_seed_walker_bip39_mnemonic.cpp sha256.c -O3 -march=native -DBIT_LENGTH=256 -o bx_seed_walker_bip39_mnemonic_256bit