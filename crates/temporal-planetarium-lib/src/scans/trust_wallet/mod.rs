pub mod lcg;
pub mod standard;

pub use standard::run as run_standard;
pub use lcg::run              as run_lcg;
pub use lcg::run_multi_file   as run_lcg_multi_file;

#[cfg(feature = "gpu")]
pub use lcg::run_bloom        as run_lcg_bloom;
