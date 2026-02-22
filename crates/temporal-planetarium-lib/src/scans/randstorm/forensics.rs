use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use bitcoin::secp256k1::SecretKey;
use anyhow::{anyhow, Result};

/// Recover a private key from two ECDSA signatures that reuse the same nonce 'k'.
/// Formula:
/// k = (z1 - z2) / (s1 - s2) mod n
/// d = (s1 * k - z1) / r mod n
///
/// z1, z2: Message hashes
/// r: Shared signature r-value
/// s1, s2: Signature s-values
pub fn recover_privkey_from_nonce_reuse(
    z1: &[u8; 32],
    z2: &[u8; 32],
    r: &[u8; 32],
    s1: &[u8; 32],
    s2: &[u8; 32],
) -> Result<SecretKey> {
    // secp256k1 order n
    let n = BigInt::from_bytes_be(Sign::Plus, &[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ]);

    let z1_bi = BigInt::from_bytes_be(Sign::Plus, z1);
    let z2_bi = BigInt::from_bytes_be(Sign::Plus, z2);
    let r_bi = BigInt::from_bytes_be(Sign::Plus, r);
    let s1_bi = BigInt::from_bytes_be(Sign::Plus, s1);
    let s2_bi = BigInt::from_bytes_be(Sign::Plus, s2);

    if s1_bi == s2_bi {
        return Err(anyhow!("s1 and s2 are identical, cannot recover k"));
    }

    // k = (z1 - z2) * inv(s1 - s2) mod n
    let mut s_diff = (&s1_bi - &s2_bi) % &n;
    if s_diff.sign() == Sign::Minus {
        s_diff += &n;
    }
    
    let s_diff_inv = mod_inverse(&s_diff, &n).ok_or_else(|| anyhow!("Failed to invert (s1 - s2)"))?;
    
    let mut z_diff = (&z1_bi - &z2_bi) % &n;
    if z_diff.sign() == Sign::Minus {
        z_diff += &n;
    }
    
    let k = (&z_diff * &s_diff_inv) % &n;

    // d = (s1 * k - z1) * inv(r) mod n
    let r_inv = mod_inverse(&r_bi, &n).ok_or_else(|| anyhow!("Failed to invert r"))?;
    
    let mut num = (&s1_bi * &k - &z1_bi) % &n;
    if num.sign() == Sign::Minus {
        num += &n;
    }
    
    let d = (&num * &r_inv) % &n;
    let (_, d_bytes) = d.to_bytes_be();
    
    // Pad to 32 bytes
    let mut padded_d = [0u8; 32];
    if d_bytes.len() > 32 {
        return Err(anyhow!("Recovered d is too large: {} bytes", d_bytes.len()));
    }
    let start = 32 - d_bytes.len();
    padded_d[start..].copy_from_slice(&d_bytes);

    SecretKey::from_slice(&padded_d).map_err(|e| anyhow!("Invalid recovered secret key: {}", e))
}

fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let (g, x, _) = egcd(a, m);
    if g == BigInt::one() {
        let mut res = x % m;
        if res.sign() == Sign::Minus {
            res += m;
        }
        Some(res)
    } else {
        None
    }
}

fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        (b.clone(), BigInt::zero(), BigInt::one())
    } else {
        let (g, x, y) = egcd(&(b % a), a);
        (g, y - (b / a) * &x, x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_reuse_recovery_smoke() {
        // Logic check: ensure egcd and mod_inverse work
        let a = BigInt::from(3);
        let m = BigInt::from(11);
        let inv = mod_inverse(&a, &m).unwrap();
        assert_eq!(inv, BigInt::from(4)); // 3 * 4 = 12 = 1 mod 11
    }
}
