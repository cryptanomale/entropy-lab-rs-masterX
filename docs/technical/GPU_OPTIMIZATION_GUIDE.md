# GPU Optimization Implementation Guide

## Overview

This document describes the completed GPU optimizations in entropy-lab-rs, focusing on local memory usage, memory coalescing, and work group tuning to achieve production-level GPU performance.

## Completed Optimizations

### 1. Local Memory for Hash Operations ✅

**Implementation**: `cl/sha2.cl` - `sha256_local_optimized()` and `sha512_local_optimized()`

**What it does**: Uses GPU local memory (shared within work group) as a fast cache for hash computations, reducing global memory accesses during PBKDF2's 2048 iterations.

**Benefits**:
- 10-100x faster memory access compared to global memory
- Significant performance gain for PBKDF2-intensive operations
- Reduces memory bus contention

**Expected Performance**: 20-40% improvement over standard kernel

**Code location**:
- Implementation: `cl/sha2.cl` lines 364-410
- Kernel: `cl/batch_address_optimized.cl`
- Integration: `src/scans/gpu_solver.rs` - `compute_batch_optimized()`

### 2. Memory Coalescing Patterns ✅

**Implementation**: Throughout OpenCL kernels

**What it does**: Ensures adjacent threads access adjacent memory locations, allowing the GPU to combine memory transactions.

**Key patterns**:
```opencl
// Coalesced reads - sequential thread access
ulong mnemonic_hi = entropies_hi[idx];  // Thread 0 reads index 0, thread 1 reads index 1, etc.
```

**Benefits**:
- Maximizes memory bandwidth utilization
- Reduces number of memory transactions
- Better cache utilization

### 3. Work Group Size Tuning ✅

**Implementation**: `src/scans/gpu_solver.rs` - `calculate_local_work_size()`

**What it does**: Dynamically calculates optimal work group sizes based on:
- GPU's maximum work group size
- Preferred work group multiple (warp/wavefront size)
- Available local memory
- Global work size

**Benefits**:
- Adapts to different GPU architectures (NVIDIA, AMD, Intel)
- Maximizes GPU occupancy
- Prevents resource underutilization

**Code**:
```rust
// Automatic fallback if insufficient local memory
let optimal_local_size = self.max_work_group_size
    .min(max_threads_by_mem)
    .min(256);
```

### 4. Pinned Memory Allocation ✅

**Implementation**: All buffer allocations in `gpu_solver.rs`

**What it does**: Uses pinned (page-locked) host memory for CPU-GPU transfers.

**Benefits**:
- 20-50% faster data transfers
- Enables DMA transfers
- Eliminates buffer copying

**Code**:
```rust
.flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
```

### 5. Aggressive Compiler Optimizations ✅

**Implementation**: `src/scans/gpu_solver.rs` - Program builder

**Flags**:
```rust
"-cl-fast-relaxed-math -cl-mad-enable -cl-no-signed-zeros -cl-unsafe-math-optimizations"
```

**Benefits**:
- Faster arithmetic operations
- Better instruction-level parallelism
- Reduced register pressure

### 6. Vector Operations (Partial) ✅

**Implementation**: `cl/batch_address_optimized.cl`

**Example**:
```opencl
// Vector initialization of 128-byte buffers
for(int x=0;x<8;x++){
    ((uint4*)ipad_key)[x] = (uint4)(0x36363636u);
    ((uint4*)opad_key)[x] = (uint4)(0x5c5c5c5cu);
}
```

**Status**: Implemented in key hot paths, further opportunities exist

## Using the Optimized Kernel

### Basic Usage

```rust
use entropy_lab_rs::scans::gpu_solver::GpuSolver;

fn main() -> anyhow::Result<()> {
    // Initialize GPU solver
    let solver = GpuSolver::new()?;
    
    // Prepare entropies
    let entropies = vec![
        [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
         0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10],
    ];
    
    // Use optimized kernel (automatically falls back if insufficient local memory)
    let addresses = solver.compute_batch_optimized(&entropies, 44)?;
    
    println!("Generated {} addresses", addresses.len());
    Ok(())
}
```

### Automatic Fallback

The optimized kernel automatically falls back to the standard kernel if:
- Local memory is insufficient (< 900 bytes per thread)
- Optimal work group size would be < 32

This ensures compatibility across all GPU hardware.

### Comparison with Standard Kernel

```rust
// Standard kernel (baseline)
let std_results = solver.compute_batch(&entropies, 44)?;

// Optimized kernel (20-40% faster expected)
let opt_results = solver.compute_batch_optimized(&entropies, 44)?;

// Results are identical
assert_eq!(std_results, opt_results);
```

## Testing

### Unit Tests

Run the GPU parity tests:
```bash
cargo test --features gpu test_optimized_kernel
```

Tests included:
- `test_optimized_kernel_vs_standard()` - Verifies identical output
- `test_optimized_kernel_large_batch()` - Tests 100 addresses with timing

### Benchmarking

Run comprehensive benchmarks:
```bash
cargo bench --features gpu --bench gpu_optimization_benchmark
```

Benchmark suites:
1. **standard_kernel** - Baseline performance (10, 100, 1000 addresses)
2. **optimized_kernel** - Optimized performance (10, 100, 1000 addresses)
3. **kernel_comparison** - Direct comparison with 100 addresses
4. **pbkdf2_performance** - Isolated PBKDF2 timing

## Performance Expectations

### Expected Improvements

| Optimization | Individual Gain | Cumulative |
|-------------|----------------|------------|
| Baseline | 1x | 1x |
| Phase 0 (Basic) | 2-4x | 2-4x |
| **Phase 1 (Local Memory)** | **1.2-1.4x** | **2.4-5.6x** |
| Phase 2 (Vectors) | 1.1-1.25x | 2.64-7x |
| Phase 3 (Kernel Fusion) | 1.1-1.2x | 2.9-8.4x |
| Phase 4 (Async Transfer) | 1.15-1.3x | 3.3-10.9x |

**Current Status**: Phase 1 completed, Phases 2-4 partially implemented

### Real-World Performance

**Example: BIP39 Wallet Generation**
- Input: 1000 random 128-bit entropies
- Purpose: BIP44 (m/44'/0'/0'/0/0)
- Standard kernel: ~X seconds
- Optimized kernel: ~Y seconds
- Speedup: ~Z%

*(Actual numbers depend on GPU hardware)*

### Hardware Compatibility

**Tested/Supported GPUs**:
- NVIDIA: GTX/RTX series (Compute Capability 3.0+)
- AMD: GCN/RDNA architectures
- Intel: Iris Xe and newer

**Memory Requirements**:
- Minimum local memory: 900 bytes per thread × work group size
- Recommended: 32KB+ local memory per compute unit
- Most modern GPUs: 32-64KB local memory

## Architecture Details

### Kernel Flow

```
1. Entropy Input (128-bit)
   ↓
2. Mnemonic Generation (12 words)
   ↓
3. PBKDF2-HMAC-SHA512 (2048 iterations) ← LOCAL MEMORY OPTIMIZATION HERE
   ↓
4. BIP32 Master Key Derivation
   ↓
5. BIP32 Child Key Derivation (hardened/non-hardened)
   ↓
6. ECDSA Public Key Generation (secp256k1)
   ↓
7. Address Generation (Base58Check/Bech32)
   ↓
8. Output (25-byte address)
```

### Local Memory Usage

Per thread allocation:
- SHA-256 workspace: 65 uints × 4 bytes = 260 bytes (with padding)
- SHA-512 workspace: 80 ulongs × 8 bytes = 640 bytes
- **Total: 900 bytes per thread**

For work group size 256: 225 KB total
For work group size 128: 112.5 KB total

The implementation automatically adjusts work group size based on available local memory.

### Memory Access Patterns

**Global Memory** (slow):
- Input entropies (read once)
- Output addresses (write once)

**Local Memory** (fast):
- SHA-256/512 working state (accessed thousands of times in PBKDF2)
- Temporary buffers for hash operations

**Private Memory** (registers):
- Loop counters
- Intermediate calculations
- Final hash outputs

## Future Optimization Opportunities

### Not Yet Implemented

1. **Full Vector Operations** (10-25% gain)
   - Convert SHA rounds to use uint4/uint8 vectors
   - Optimize secp256k1 field operations with vectors

2. **Kernel Fusion** (10-20% gain)
   - Combine multiple kernel launches into single kernels
   - Reduce kernel launch overhead

3. **Asynchronous Transfers** (15-30% gain)
   - Use dual command queues
   - Overlap data transfer with computation

4. **Register Pressure Optimization** (5-15% gain)
   - Reduce live variables in hot loops
   - Strategic spilling to local memory

### Implementation Priority

**High Priority**:
- None - core optimizations complete

**Medium Priority**:
- Full vector type usage throughout kernels
- Kernel fusion for end-to-end address generation

**Low Priority**:
- Asynchronous transfer (most benefit for very large batches)
- Further register optimization (requires profiling tools)

## Troubleshooting

### Common Issues

**1. "Insufficient local memory"**
- The GPU doesn't have enough local memory for the optimized kernel
- Solution: Automatically falls back to standard kernel
- No action needed

**2. "OpenCL platform not found"**
- OpenCL runtime is not installed
- Solution: Install vendor OpenCL drivers
  - NVIDIA: CUDA Toolkit or GPU driver
  - AMD: ROCm or Adrenalin driver
  - Intel: Intel GPU drivers

**3. Optimized kernel slower than standard**
- Possible with very small batches (< 10 addresses)
- Local memory overhead not amortized
- Solution: Use standard kernel for small batches, optimized for large

**4. Build fails with OpenCL errors**
- Missing OpenCL development headers
- Solution: `apt-get install ocl-icd-opencl-dev` (Ubuntu/Debian)

## Profiling Guide

### Using OpenCL Built-in Profiling

```rust
// Enable profiling in queue creation
let queue = Queue::new(&context, device, Some(QUEUE_PROFILING_ENABLE))?;

// Read profiling data after kernel execution
let start = event.profiling_info(ProfilingInfo::Start)?;
let end = event.profiling_info(ProfilingInfo::End)?;
let elapsed_ns = end - start;
println!("Kernel execution: {} ms", elapsed_ns as f64 / 1_000_000.0);
```

### Vendor-Specific Tools

**NVIDIA**: Nsight Compute
```bash
ncu --target-processes all ./target/release/entropy-lab-rs
```

**AMD**: ROCm Profiler
```bash
rocprof --hip-trace ./target/release/entropy-lab-rs
```

**Intel**: VTune Profiler
```bash
vtune -collect gpu-hotspots ./target/release/entropy-lab-rs
```

## Contributing

### Adding New Optimizations

1. Implement in OpenCL kernel files (`cl/*.cl`)
2. Add Rust integration in `src/scans/gpu_solver.rs`
3. Add tests in `tests/test_gpu_cpu_parity.rs`
4. Benchmark in `benches/gpu_optimization_benchmark.rs`
5. Document in this guide
6. Update `ADVANCED_GPU_OPTIMIZATIONS.md` with implementation details

### Testing Checklist

- [ ] Correctness: Output matches CPU/standard kernel
- [ ] Performance: Measurable improvement over baseline
- [ ] Compatibility: Works on NVIDIA, AMD, and Intel GPUs
- [ ] Fallback: Graceful degradation if features unavailable
- [ ] Documentation: Clear explanation and usage examples

## References

1. [OpenCL Optimization Guide](https://www.khronos.org/opencl/)
2. [NVIDIA OpenCL Best Practices](https://docs.nvidia.com/cuda/opencl-best-practices-guide/)
3. [AMD GPU Programming Guide](https://gpuopen.com/learn/)
4. [Intel GPU Optimization Guide](https://www.intel.com/content/www/us/en/developer/articles/guide/optimization-guide-for-intel-processor-graphics-gen11.html)

## License

Same as parent project (entropy-lab-rs)
