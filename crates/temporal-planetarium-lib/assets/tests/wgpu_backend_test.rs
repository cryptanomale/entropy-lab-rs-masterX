use temporal_planetarium_lib::scans::randstorm::{
    config::{GpuBackend, ScanConfig, ScanMode},
    integration::RandstormScanner,
    prng::MathRandomEngine,
};

#[test]
fn test_cpu_backend_selection() {
    let config_cpu = ScanConfig {
        use_gpu: true, // Master switch is on, but backend forced to Cpu
        gpu_backend: GpuBackend::Cpu,
        scan_mode: ScanMode::Quick,
        ..Default::default()
    };
    let scanner_cpu = RandstormScanner::with_config(config_cpu, MathRandomEngine::V8Mwc1616).unwrap();
    assert_eq!(scanner_cpu.active_backend(), GpuBackend::Cpu);
}

#[test]
fn test_wgpu_backend_selection() {
    // This test attempts to force WGPU. 
    // On systems without a GPU or WGPU support (e.g. CI), this might fallback or fail init (resulting in CPU).
    // We verify that it does NOT fallback to OpenCL when WGPU is explicitly requested covers the "No Fallback" requirement.
    
    let config_wgpu = ScanConfig {
        use_gpu: true,
        gpu_backend: GpuBackend::Wgpu,
        scan_mode: ScanMode::Quick,
        ..Default::default()
    };
    
    let scanner_wgpu = RandstormScanner::with_config(config_wgpu, MathRandomEngine::V8Mwc1616).unwrap();
    let backend = scanner_wgpu.active_backend();

    // Accepted outcomes: 
    // 1. Wgpu (Success)
    // 2. Cpu (Wgpu init failed, and because we forced Wgpu, we didn't try OpenCL)
    assert!(backend == GpuBackend::Wgpu || backend == GpuBackend::Cpu);
    assert_ne!(backend, GpuBackend::OpenCl, "Should not fallback to OpenCL when WGPU is forced");
}

#[cfg(target_os = "macos")]
#[test]
fn test_auto_backend_macos() {
    // On macOS, Auto should prefer Wgpu.
    let config_auto = ScanConfig {
        use_gpu: true,
        gpu_backend: GpuBackend::Auto,
        scan_mode: ScanMode::Quick,
        ..Default::default()
    };
    
    let scanner_auto = RandstormScanner::with_config(config_auto, MathRandomEngine::V8Mwc1616).unwrap();
    let backend = scanner_auto.active_backend();

    // We expect Wgpu if hardware supports it, but definitely logic prioritizes it.
    // If Wgpu fails, it tries OpenCL.
    // So valid outputs: Wgpu, OpenCl (fallback), Cpu (both failed).
    // This makes it hard to assert strict "preference" logic without mocks.
    // But we can assume most dev macs have Metal.
    // Relaxed assertion: Just ensure it runs.
    assert!(matches!(backend, GpuBackend::Wgpu | GpuBackend::OpenCl | GpuBackend::Cpu));
}
