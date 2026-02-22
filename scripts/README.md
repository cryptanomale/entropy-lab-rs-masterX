# Scripts Directory

This directory contains utility scripts for testing, validation, and automation.

## Shell Scripts

- **scan_all.sh** - Run all vulnerability scans
- **test_gpu_bip39.sh** - Test GPU BIP39 validation
- **quick_validate.sh** - Quick validation of scanner outputs
- **validate_gpu_complete.sh** - Complete GPU validation suite

## Python Scripts

- **check_mnemonics.py** - Verify mnemonic generation correctness
- **test_cpu_reference.py** - CPU reference implementation for testing
- **validate_cake.py** - Validate Cake Wallet scanner results
- **validate_gpu.py** - Validate GPU kernel outputs against CPU

## Usage

These scripts are primarily used for development and testing. They may require:
- Python 3.x with appropriate dependencies
- Rust toolchain
- Bitcoin RPC access (for some scripts)

See individual script comments for specific usage instructions.
