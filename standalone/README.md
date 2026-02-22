# Standalone Programs Directory

This directory contains standalone programs and utilities that are independent of the main crate. They are not built automatically with the main project.

## Files

### validate_cpu.rs
CPU reference implementation for address validation. This can be compiled standalone to verify address generation without the full crate.

**Note**: This file may have compilation errors as it's a standalone program with its own dependencies.

### gpu_bip39_validator.rs
Standalone GPU BIP39 validation utility. Demonstrates GPU-accelerated BIP39 mnemonic validation.

**Note**: This requires OpenCL and has dependencies that are not part of the main project.

### bip39_solver_main.rs / bip39_solver_Cargo.toml
Alternative BIP39 solver implementation with its own Cargo configuration. This is a completely separate project.

## Building Standalone Programs

These programs are **not** built as part of the main project. They are kept here for reference and can be built manually if needed:

### validate_cpu.rs
```bash
rustc --edition 2021 validate_cpu.rs -o validate_cpu
# Note: May need to add dependencies
```

### bip39_solver
```bash
# This requires its own project setup
# Use bip39_solver_Cargo.toml as Cargo.toml in a new project
```

## Purpose

These standalone programs serve as:
- Reference implementations for testing and comparison
- Standalone tools for specific tasks
- Alternative approaches to solving similar problems
- Historical artifacts from development iterations

**Note**: These files are kept for reference but may not be maintained as the main project evolves.
