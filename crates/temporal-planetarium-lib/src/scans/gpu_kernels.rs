use ocl::{Context, Program};
use std::fs;
use std::path::Path;

#[cfg(feature = "use_opencl")]
pub fn build_program(context: &Context) -> ocl::Result<Program> {
    let mut source = String::new();

    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("cl");

    let files = [
        "common",
        "sha2",
        "sha512",
        "keccak256",
        "profanity",
        // ⚠️ добавляй ТОЛЬКО если реально используются ядра
    ];

    for f in files {
        let path = base.join(format!("{}.cl", f));
        let code = fs::read_to_string(&path)
            .map_err(|e| ocl::Error::from(format!(
                "Failed to read {:?}: {}",
                path, e
            )))?;
        source.push_str(&code);
        source.push('\n');
    }

    //Program::builder()
        .src(source)
        .build(context)
}
