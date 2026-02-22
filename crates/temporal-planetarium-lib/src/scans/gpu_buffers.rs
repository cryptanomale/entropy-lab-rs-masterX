// temporal_planetarium_lib/gpu/buffers.rs

use ocl::{Buffer, Queue, flags};
use super::gpu_constants::{SHA512_K, KECCAK_RC};

pub struct GpuConstBuffers {
    pub sha512_k: Buffer<u64>,
    pub keccak_rc: Buffer<u64>,
}

impl GpuConstBuffers {
    pub fn new(queue: &Queue) -> ocl::Result<Self> {
        let sha512_k = Buffer::<u64>::builder()
            .queue(queue.clone())
            .flags(flags::MEM_READ_ONLY | flags::MEM_COPY_HOST_PTR)
            .len(SHA512_K.len())
            .copy_host_slice(&SHA512_K)
            .build()?;

        let keccak_rc = Buffer::<u64>::builder()
            .queue(queue.clone())
            .flags(flags::MEM_READ_ONLY | flags::MEM_COPY_HOST_PTR)
            .len(KECCAK_RC.len())
            .copy_host_slice(&KECCAK_RC)
            .build()?;

        Ok(Self {
            sha512_k,
            keccak_rc,
        })
    }
}
