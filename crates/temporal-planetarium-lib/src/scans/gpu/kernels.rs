// temporal_planetarium_lib/gpu/kernels.rs

use std::fs;
use std::path::Path;
use ocl::{Context, Program};

fn read_kernel(path: &str) -> std::io::Result<String> {
    fs::read_to_string(Path::new(path))
}

pub fn build_program(context: &Context) -> ocl::Result<Program> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("cl")
		.join("gpu.cl");

	let src = std::fs::read_to_string(&path).map_err(|e| {
		ocl::Error::from(format!("Failed to read {:?}: {}", path, e))
	})?;

    source.push_str(&read_kernel("kernels/sha512.cl")?);
    source.push('\n');

    source.push_str(&read_kernel("kernels/keccak.cl")?);
    source.push('\n');

    source.push_str(&read_kernel("kernels/profanity.cl")?);
    source.push('\n');

    Program::builder()
        .src(source)
        .build(context)
}
