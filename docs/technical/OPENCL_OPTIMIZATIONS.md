# OpenCL GPU Optimizations

This document describes the comprehensive OpenCL optimizations implemented in the entropy-lab-rs project.

## Overview

The project uses OpenCL for GPU-accelerated cryptocurrency wallet vulnerability scanning. This document details the optimizations applied to maximize GPU performance.

## Implemented Optimizations

### 1. Device-Aware Work Group Sizing

**Location:** `src/scans/gpu_solver.rs` - `GpuSolver::new()`

**What:** Query GPU device capabilities at initialization and dynamically adjust work group sizes.

**Benefits:**
- Eliminates hardcoded work group sizes (previously 256 for all GPUs)
- Adapts to different GPU architectures (NVIDIA, AMD, Intel)
- Maximizes GPU occupancy by using device-specific parameters

**Implementation:**
- Query `max_wg_size()` for maximum work group size
- Query `PreferredWorkGroupSizeMultiple` for warp/wavefront size
- Query `max_compute_units()` and `local_mem_size()` for resource planning
- Dynamic calculation in `calculate_local_work_size()` method

**Expected Improvement:** 10-30% performance gain depending on GPU architecture

### 2. Pinned Memory Allocation

**Location:** All buffer allocations in `gpu_solver.rs`

**What:** Use pinned (page-locked) host memory for CPU-GPU data transfers.

**Benefits:**
- Faster data transfers between CPU and GPU
- Eliminates buffer copying during transfers
- Enables DMA (Direct Memory Access) transfers

**Implementation:**
```rust
.flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
```

**Expected Improvement:** 20-50% faster data transfer, especially for large batches

### 3. Aggressive Compiler Optimizations

**Location:** `src/scans/gpu_solver.rs` - Program builder

**What:** Enable aggressive math optimizations in the OpenCL compiler.

**Flags Added:**
- `-cl-fast-relaxed-math`: Enable faster, less precise math operations
- `-cl-mad-enable`: Enable multiply-add instruction fusion
- `-cl-no-signed-zeros`: Treat +0.0 and -0.0 as equivalent
- `-cl-unsafe-math-optimizations`: Enable aggressive optimizations

**Benefits:**
- Faster arithmetic operations
- Better instruction-level parallelism
- Reduced register pressure

**Expected Improvement:** 5-15% performance gain for math-heavy kernels

### 4. Memory Access Coalescing

**Location:** OpenCL kernel implementations

**What:** Aligned memory access patterns for optimal GPU memory bandwidth.

**Implementation:**
- Use `__attribute__((aligned(4)))` for buffer declarations
- Ensure contiguous memory access patterns
- Pack data structures to minimize padding

**Benefits:**
- Maximizes memory bandwidth utilization
- Reduces memory transactions
- Better cache utilization

**Expected Improvement:** 10-40% depending on memory access patterns

### 5. Compute Unit Occupancy Optimization

**Location:** `calculate_optimal_batch_size()` method

**What:** Calculate optimal batch sizes based on GPU compute units.

**Implementation:**
```rust
let optimal_size = (compute_units * max_work_group_size * occupancy_factor);
```

**Benefits:**
- Keeps GPU fully occupied
- Balances work distribution across compute units
- Prevents resource underutilization

**Expected Improvement:** 15-25% better GPU utilization

## Performance Testing

### Recommended Benchmarks

1. **BIP39 Address Generation** (`compute_batch`)
   - Measure throughput (addresses/second)
   - Test with batch sizes: 1K, 10K, 100K, 1M

2. **Cake Hash Searching** (`compute_cake_hash`)
   - Measure search speed (hashes/second)
   - Test with various timestamp ranges

3. **Mobile Sensor Cracking** (`compute_mobile_crack`)
   - Measure brute-force speed
   - Full search space: ~8.1M combinations

### Profiling Tools

Use these tools to validate optimizations:

- **AMD CodeXL**: For AMD GPUs
- **NVIDIA Nsight Compute**: For NVIDIA GPUs
- **Intel VTune**: For Intel GPUs
- **OpenCL Profiling API**: Built into ocl crate

### Expected Overall Performance Gain

Combined effect of all optimizations: **2-4x performance improvement**

Actual gains depend on:
- GPU architecture
- Kernel complexity
- Memory transfer vs. computation ratio
- Batch sizes

## Future Optimization Opportunities

### 1. Kernel Fusion
Combine multiple kernel launches into single kernels to reduce overhead.

**Potential Gain:** 10-20%

### 2. Asynchronous Transfers
Overlap data transfer with computation using multiple command queues.

**Potential Gain:** 15-30%

### 3. Local Memory Utilization
Use shared local memory for frequently accessed data (e.g., S-boxes, constants).

**Potential Gain:** 20-40% for memory-bound kernels

### 4. Vector Operations
Use vector data types (float4, int4) for SIMD operations.

**Potential Gain:** 10-25%

### 5. Constant Memory Caching
Move read-only lookup tables to constant memory space.

**Potential Gain:** 5-15%

## CUDA Support

**Status:** Not implemented

**Rationale:** 
- Project uses OpenCL for cross-platform GPU support
- OpenCL works on NVIDIA, AMD, and Intel GPUs
- CUDA would limit to NVIDIA-only
- OpenCL provides sufficient performance

**If CUDA Support Needed:**
- Would require parallel CUDA implementations of all kernels
- Use cuBLAS/cuFFT for optimized primitives
- Leverage CUDA-specific features (warp shuffle, dynamic parallelism)
- Expected similar or slightly better performance on NVIDIA GPUs

## Memory Optimization Best Practices

1. **Buffer Reuse**: Reuse buffers across kernel invocations when possible
2. **Proper Flags**: Use correct `MemFlags` for intended usage patterns
3. **Minimize Transfers**: Compute as much as possible on GPU
4. **Batch Processing**: Process data in large batches to amortize transfer costs

## Profiling Results Template

```
GPU Model: [Device Name]
Driver Version: [Version]
OpenCL Version: [Version]

Kernel: [kernel_name]
Batch Size: [size]

Before Optimization:
- Execution Time: [X] ms
- Throughput: [Y] ops/sec
- GPU Utilization: [Z]%

After Optimization:
- Execution Time: [X] ms
- Throughput: [Y] ops/sec
- GPU Utilization: [Z]%

Improvement: [X]%
```

## Verification

All optimizations preserve correctness:
- Existing test vectors pass
- Output matches CPU reference implementations
- No precision loss in critical operations

## Maintenance Notes

- Test on multiple GPU architectures before release
- Profile after significant kernel changes
- Monitor for regressions in performance tests
- Update this document when adding new optimizations
