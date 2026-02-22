use anyhow::Result;
use std::sync::{Arc, Mutex};
use std::thread;

#[cfg(feature = "gui")]
use eframe::egui;

#[derive(Default, Clone, Copy, PartialEq)]
pub enum ScannerType {
    #[default]
    CakeWallet,
    CakeWalletTargeted,
    TrustWallet,
    MobileSensor,
    MilkSad,
    Profanity,
    AndroidSecureRandom,
    CakeWalletDartPrng,
}

impl ScannerType {
    fn name(&self) -> &str {
        match self {
            ScannerType::CakeWallet => "Cake Wallet (2024)",
            ScannerType::CakeWalletTargeted => "Cake Wallet Targeted",
            ScannerType::TrustWallet => "Trust Wallet (2023)",
            ScannerType::MobileSensor => "Mobile Sensor Entropy",
            ScannerType::MilkSad => "Libbitcoin Milk Sad",
            ScannerType::Profanity => "Profanity Vanity Address",
            ScannerType::AndroidSecureRandom => "Android SecureRandom",
            ScannerType::CakeWalletDartPrng => "Cake Wallet Dart PRNG",
        }
    }

    fn description(&self) -> &str {
        match self {
            ScannerType::CakeWallet => "Scans for Cake Wallet 2024 vulnerability using Electrum seed format. Searches 2^20 (1,048,576) entropy space.",
            ScannerType::CakeWalletTargeted => "Scans only the 8,757 confirmed vulnerable Cake Wallet seeds (GPU accelerated).",
            ScannerType::TrustWallet => "Reproduces Trust Wallet MT19937 weakness (CVE-2023-31290).",
            ScannerType::MobileSensor => "Tests mobile sensor-based entropy vulnerabilities.",
            ScannerType::MilkSad => "Scans for Milk Sad vulnerability (CVE-2023-39910). Discovered 224k+ vulnerable wallets in 2018.",
            ScannerType::Profanity => "Scans for Profanity vanity address vulnerabilities (CVE-2022-40769).",
            ScannerType::AndroidSecureRandom => "Detects duplicate R values in ECDSA signatures (2013 vulnerability).",
            ScannerType::CakeWalletDartPrng => "Reverse-engineers Cake Wallet seeds using time-based Dart PRNG (2020-2021).",
        }
    }

    fn gpu_supported(&self) -> bool {
        matches!(
            self,
            ScannerType::CakeWallet
                | ScannerType::CakeWalletTargeted
                | ScannerType::TrustWallet
                | ScannerType::MobileSensor
                | ScannerType::MilkSad
                | ScannerType::Profanity
                | ScannerType::CakeWalletDartPrng
        )
    }
}

#[derive(Default, Clone)]
pub struct ScanConfig {
    pub scanner_type: ScannerType,
    pub limit: Option<u32>,
    pub target: String,
    pub start_timestamp: Option<u32>,
    pub end_timestamp: Option<u32>,
    pub multipath: bool,
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_pass: String,
    pub start_block: u64,
    pub end_block: u64,
    pub use_gpu: bool,
}

#[derive(Clone)]
pub enum ScanStatus {
    Idle,
    Running { progress: f32, message: String },
    Completed { result: String },
    Error { error: String },
}

impl Default for ScanStatus {
    fn default() -> Self {
        ScanStatus::Idle
    }
}

pub struct EntropyLabApp {
    config: ScanConfig,
    status: Arc<Mutex<ScanStatus>>,
    scan_thread: Option<thread::JoinHandle<()>>,
    gpu_available: bool,
    show_advanced: bool,
}

impl Default for EntropyLabApp {
    fn default() -> Self {
        // Check GPU availability
        let gpu_available = check_gpu_availability();

        Self {
            config: ScanConfig {
                rpc_url: "http://127.0.0.1:8332".to_string(),
                start_block: 302000,
                end_block: 330000,
                use_gpu: gpu_available,
                ..Default::default()
            },
            status: Arc::new(Mutex::new(ScanStatus::Idle)),
            scan_thread: None,
            gpu_available,
            show_advanced: false,
        }
    }
}

#[cfg(feature = "gui")]
impl eframe::App for EntropyLabApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔐 Entropy Lab RS - Wallet Vulnerability Scanner");
            ui.add_space(10.0);

            // GPU Status indicator
            ui.horizontal(|ui| {
                if self.gpu_available {
                    ui.colored_label(egui::Color32::GREEN, "● GPU Available");
                } else {
                    ui.colored_label(egui::Color32::YELLOW, "● GPU Not Available (CPU mode)");
                }
            });
            ui.add_space(10.0);

            ui.separator();
            ui.add_space(10.0);

            // Scanner Selection
            ui.group(|ui| {
                ui.heading("Scanner Selection");
                ui.add_space(5.0);

                egui::ComboBox::from_label("Vulnerability Scanner")
                    .selected_text(self.config.scanner_type.name())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.config.scanner_type,
                            ScannerType::CakeWallet,
                            ScannerType::CakeWallet.name(),
                        );
                        ui.selectable_value(
                            &mut self.config.scanner_type,
                            ScannerType::CakeWalletTargeted,
                            ScannerType::CakeWalletTargeted.name(),
                        );
                        ui.selectable_value(
                            &mut self.config.scanner_type,
                            ScannerType::TrustWallet,
                            ScannerType::TrustWallet.name(),
                        );
                        ui.selectable_value(
                            &mut self.config.scanner_type,
                            ScannerType::MobileSensor,
                            ScannerType::MobileSensor.name(),
                        );
                        ui.selectable_value(
                            &mut self.config.scanner_type,
                            ScannerType::MilkSad,
                            ScannerType::MilkSad.name(),
                        );
                        ui.selectable_value(
                            &mut self.config.scanner_type,
                            ScannerType::Profanity,
                            ScannerType::Profanity.name(),
                        );
                        ui.selectable_value(
                            &mut self.config.scanner_type,
                            ScannerType::AndroidSecureRandom,
                            ScannerType::AndroidSecureRandom.name(),
                        );
                        ui.selectable_value(
                            &mut self.config.scanner_type,
                            ScannerType::CakeWalletDartPrng,
                            ScannerType::CakeWalletDartPrng.name(),
                        );
                    });

                ui.add_space(5.0);
                ui.label(self.config.scanner_type.description());

                if self.config.scanner_type.gpu_supported() {
                    ui.add_space(5.0);
                    ui.colored_label(egui::Color32::GREEN, "✓ GPU Acceleration Available");
                }
            });

            ui.add_space(10.0);

            // Configuration
            ui.group(|ui| {
                ui.heading("Configuration");
                ui.add_space(5.0);

                // Common options
                match self.config.scanner_type {
                    ScannerType::CakeWallet => {
                        ui.horizontal(|ui| {
                            ui.label("Scan Limit:");
                            let mut limit_str = self
                                .config
                                .limit
                                .map(|l| l.to_string())
                                .unwrap_or_else(|| "1048576".to_string());
                            if ui.text_edit_singleline(&mut limit_str).changed() {
                                self.config.limit = limit_str.parse().ok();
                            }
                        });
                    }
                    ScannerType::TrustWallet
                    | ScannerType::MobileSensor
                    | ScannerType::Profanity => {
                        ui.horizontal(|ui| {
                            ui.label("Target Address:");
                            ui.text_edit_singleline(&mut self.config.target);
                        });
                    }
                    ScannerType::MilkSad => {
                        ui.horizontal(|ui| {
                            ui.label("Start Timestamp:");
                            let mut ts_str = self
                                .config
                                .start_timestamp
                                .map(|t| t.to_string())
                                .unwrap_or_default();
                            if ui.text_edit_singleline(&mut ts_str).changed() {
                                self.config.start_timestamp = ts_str.parse().ok();
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label("End Timestamp:");
                            let mut ts_str = self
                                .config
                                .end_timestamp
                                .map(|t| t.to_string())
                                .unwrap_or_default();
                            if ui.text_edit_singleline(&mut ts_str).changed() {
                                self.config.end_timestamp = ts_str.parse().ok();
                            }
                        });
                        ui.checkbox(&mut self.config.multipath, "Multi-path derivation");
                    }
                    ScannerType::AndroidSecureRandom => {
                        ui.horizontal(|ui| {
                            ui.label("Start Block:");
                            let mut block_str = self.config.start_block.to_string();
                            if ui.text_edit_singleline(&mut block_str).changed() {
                                self.config.start_block = block_str.parse().unwrap_or(302000);
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label("End Block:");
                            let mut block_str = self.config.end_block.to_string();
                            if ui.text_edit_singleline(&mut block_str).changed() {
                                self.config.end_block = block_str.parse().unwrap_or(330000);
                            }
                        });
                    }
                    _ => {}
                }

                // Advanced options
                if matches!(
                    self.config.scanner_type,
                    ScannerType::AndroidSecureRandom | ScannerType::MilkSad
                ) {
                    ui.add_space(5.0);
                    if ui
                        .button(if self.show_advanced {
                            "▼ Hide Advanced Options"
                        } else {
                            "▶ Show Advanced Options"
                        })
                        .clicked()
                    {
                        self.show_advanced = !self.show_advanced;
                    }

                    if self.show_advanced {
                        ui.add_space(5.0);
                        ui.horizontal(|ui| {
                            ui.label("RPC URL:");
                            ui.text_edit_singleline(&mut self.config.rpc_url);
                        });
                        ui.horizontal(|ui| {
                            ui.label("RPC User:");
                            ui.text_edit_singleline(&mut self.config.rpc_user);
                        });
                        ui.horizontal(|ui| {
                            ui.label("RPC Password:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.config.rpc_pass)
                                    .password(true),
                            );
                        });
                    }
                }

                // GPU toggle
                if self.gpu_available && self.config.scanner_type.gpu_supported() {
                    ui.add_space(5.0);
                    ui.checkbox(&mut self.config.use_gpu, "Use GPU Acceleration");
                }
            });

            ui.add_space(10.0);

            // Control buttons
            ui.horizontal(|ui| {
                let is_running = matches!(*self.status.lock().unwrap(), ScanStatus::Running { .. });

                if ui
                    .add_enabled(!is_running, egui::Button::new("▶ Start Scan"))
                    .clicked()
                {
                    self.start_scan();
                }

                if ui
                    .add_enabled(is_running, egui::Button::new("⏹ Stop Scan"))
                    .clicked()
                {
                    self.stop_scan();
                }

                if ui.button("🔄 Reset").clicked() {
                    self.config = ScanConfig {
                        rpc_url: "http://127.0.0.1:8332".to_string(),
                        start_block: 302000,
                        end_block: 330000,
                        use_gpu: self.gpu_available,
                        ..Default::default()
                    };
                }
            });

            ui.add_space(10.0);

            // Status display
            ui.group(|ui| {
                ui.heading("Status");
                ui.add_space(5.0);

                let status = self.status.lock().unwrap().clone();
                match status {
                    ScanStatus::Idle => {
                        ui.label("Ready to scan. Select a scanner and click Start.");
                    }
                    ScanStatus::Running { progress, message } => {
                        ui.label(&message);
                        ui.add_space(5.0);
                        ui.add(egui::ProgressBar::new(progress).show_percentage());
                    }
                    ScanStatus::Completed { result } => {
                        ui.colored_label(egui::Color32::GREEN, "✓ Scan completed!");
                        ui.add_space(5.0);
                        egui::ScrollArea::vertical()
                            .max_height(200.0)
                            .show(ui, |ui| {
                                ui.monospace(&result);
                            });
                    }
                    ScanStatus::Error { error } => {
                        ui.colored_label(egui::Color32::RED, "✗ Error:");
                        ui.add_space(5.0);
                        egui::ScrollArea::vertical()
                            .max_height(200.0)
                            .show(ui, |ui| {
                                ui.monospace(&error);
                            });
                    }
                }
            });

            ui.add_space(10.0);

            // Footer with warning
            ui.separator();
            ui.add_space(5.0);
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::from_rgb(255, 165, 0), "⚠ Warning:");
                ui.label("This tool is for authorized security research only.");
            });
        });

        // Request repaint if scan is running to update progress
        if matches!(*self.status.lock().unwrap(), ScanStatus::Running { .. }) {
            ctx.request_repaint();
        }
    }
}

impl EntropyLabApp {
    fn start_scan(&mut self) {
        let status = Arc::clone(&self.status);
        let config = self.config.clone();

        // Update status
        *status.lock().unwrap() = ScanStatus::Running {
            progress: 0.0,
            message: format!("Starting {} scan...", config.scanner_type.name()),
        };

        // Spawn scan thread
        let handle = thread::spawn(move || {
            let result = run_scan(&config, Arc::clone(&status));

            match result {
                Ok(output) => {
                    *status.lock().unwrap() = ScanStatus::Completed { result: output };
                }
                Err(e) => {
                    *status.lock().unwrap() = ScanStatus::Error {
                        error: e.to_string(),
                    };
                }
            }
        });

        self.scan_thread = Some(handle);
    }

    fn stop_scan(&mut self) {
        // Note: Complete thread cancellation would require additional infrastructure
        // such as Arc<AtomicBool> or channels for cooperative cancellation.
        // For now, we update the UI state. The scan thread will complete its current operation.
        *self.status.lock().unwrap() = ScanStatus::Idle;

        // Future enhancement: Add proper cancellation mechanism
        // This would require passing a cancellation token to run_scan()
    }
}

fn check_gpu_availability() -> bool {
    #[cfg(feature = "gpu")]
    {
        use crate::scans::gpu_solver::GpuSolver;
        GpuSolver::new().is_ok()
    }
    #[cfg(not(feature = "gpu"))]
    {
        false
    }
}

fn run_scan(config: &ScanConfig, status: Arc<Mutex<ScanStatus>>) -> Result<String> {
    use crate::scans;

    // Update progress
    *status.lock().unwrap() = ScanStatus::Running {
        progress: 0.1,
        message: format!("Running {} scanner...", config.scanner_type.name()),
    };

    let result = match config.scanner_type {
        ScannerType::CakeWallet => {
            scans::cake_wallet::run(config.limit)?;
            "Cake Wallet scan completed successfully.".to_string()
        }
        ScannerType::CakeWalletTargeted => {
            scans::cake_wallet_targeted::run_targeted()?;
            "Cake Wallet Targeted scan completed successfully.".to_string()
        }
        ScannerType::TrustWallet => {
            scans::trust_wallet::run(if config.target.is_empty() {
                None
            } else {
                Some(config.target.clone())
            })?;
            "Trust Wallet scan completed successfully.".to_string()
        }
        ScannerType::MobileSensor => {
            scans::mobile_sensor::run(if config.target.is_empty() {
                None
            } else {
                Some(config.target.clone())
            })?;
            "Mobile Sensor scan completed successfully.".to_string()
        }
        ScannerType::MilkSad => {
            let rpc_config = if !config.rpc_url.is_empty() && !config.rpc_user.is_empty() {
                Some((
                    config.rpc_url.clone(),
                    config.rpc_user.clone(),
                    config.rpc_pass.clone(),
                ))
            } else {
                None
            };

            scans::milk_sad::run_scan(
                if config.target.is_empty() {
                    None
                } else {
                    Some(config.target.clone())
                },
                config.start_timestamp,
                config.end_timestamp,
                config.multipath,
                rpc_config,
            )?;
            "Milk Sad scan completed successfully.".to_string()
        }
        ScannerType::Profanity => {
            scans::profanity::run(if config.target.is_empty() {
                None
            } else {
                Some(config.target.clone())
            })?;
            "Profanity scan completed successfully.".to_string()
        }
        ScannerType::AndroidSecureRandom => {
            scans::android_securerandom::run(
                &config.rpc_url,
                &config.rpc_user,
                &config.rpc_pass,
                config.start_block,
                config.end_block,
            )?;
            "Android SecureRandom scan completed successfully.".to_string()
        }
        ScannerType::CakeWalletDartPrng => {
            scans::cake_wallet_dart_prng::run()?;
            "Cake Wallet Dart PRNG scan completed successfully.".to_string()
        }
    };

    // Update to completed
    *status.lock().unwrap() = ScanStatus::Running {
        progress: 1.0,
        message: "Finalizing results...".to_string(),
    };

    Ok(result)
}

#[cfg(feature = "gui")]
pub fn run_gui() -> Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 700.0])
            .with_min_inner_size([700.0, 500.0])
            .with_icon(
                eframe::icon_data::from_png_bytes(&include_bytes!("../assets/icon.png")[..])
                    .unwrap_or_else(|e| {
                        eprintln!("Warning: Failed to load app icon: {}", e);
                        Default::default()
                    }),
            ),
        ..Default::default()
    };

    eframe::run_native(
        "Entropy Lab RS",
        native_options,
        Box::new(|_cc| Ok(Box::new(EntropyLabApp::default()))),
    )
    .map_err(|e| anyhow::anyhow!("Failed to start GUI: {}", e))
}

#[cfg(not(feature = "gui"))]
pub fn run_gui() -> Result<()> {
    anyhow::bail!("GUI feature is not enabled. Please compile with --features gui")
}
