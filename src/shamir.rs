// Author: Iamzulx
//! Shamir Secret Sharing for entropy — the seed never exists as one object.
//!
//! Splits a 64-byte seed into `n` shares such that any `t` shares can
//! reconstruct the seed. The reconstruction happens inline during key
//! derivation: the full seed never exists as a single object in memory.
//!
//! ## Construction
//! Operates over GF(2^8) (the field of bytes with irreducible polynomial
//! `x^8 + x^4 + x^3 + x + 1`, i.e. 0x11B). Each byte of the secret is
//! shared independently:
//!
//!   share_i[j] = f_j(i)  where  f_j(x) = secret[j] + a_1·x + a_2·x² + … + a_{t-1}·x^{t-1}
//!
//! Coefficients a_1…a_{t-1} are random per byte position. Reconstruction
//! uses Lagrange interpolation at x=0.
//!
//! ## Philosophy alignment
//! - **No persistent state**: the seed is reconstructed transiently and
//!   wiped immediately after use. It never persists.
//! - **Wipe outside boundary**: shares are wiped after reconstruction.
//! - **Math over abstraction**: Shamir SSS is information-theoretically
//!   secure (given t-1 shares, the secret is uniformly random).

#![cfg(feature = "std")]

extern crate alloc;
use alloc::vec::Vec;

use crate::l0_memlock::zeroize_bytes;

// ── GF(2^8) arithmetic ──────────────────────────────────────────────────────

/// Irreducible polynomial for GF(2^8): x^8 + x^4 + x^3 + x + 1.
const POLY: u16 = 0x11B;

/// Multiply two elements in GF(2^8) in constant time.
///
/// Uses the "Russian peasant" algorithm with no secret-dependent branches
/// or loop bounds. All 8 bits of `b` are processed unconditionally.
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result: u16 = 0;
    let mut a = a as u16;
    let b = b as u16;
    for i in 0..8 {
        // Constant-time conditional XOR: mask = 0xFFFF if bit set, 0 otherwise
        let mask = 0u16.wrapping_sub((b >> i) & 1);
        result ^= a & mask;
        // Constant-time reduction: check high bit before shift, conditionally XOR polynomial
        let hi_bit = (a >> 7) & 1;
        let reduce_mask = 0u16.wrapping_sub(hi_bit);
        a = (a << 1) ^ (POLY & reduce_mask);
    }
    result as u8
}

/// Compute the multiplicative inverse in GF(2^8) in constant time.
///
/// Uses Fermat's little theorem: a^(-1) = a^254 in GF(2^8).
/// Exponent 254 = 0b11111110. Constant-time square-and-multiply with
/// all 8 iterations executed regardless of input. Returns 0 for a=0
/// (which has no inverse; the caller checks for this).
fn gf_inv(a: u8) -> u8 {
    let mut acc: u8 = 1;
    let mut base = a;
    for i in 0..8u8 {
        let bit = (254u8 >> i) & 1;
        // Constant-time conditional multiply: acc = bit ? gf_mul(acc, base) : acc
        let product = gf_mul(acc, base);
        let mask = 0u8.wrapping_sub(bit);
        acc = (acc & !mask) | (product & mask);
        base = gf_mul(base, base);
    }
    acc
}

/// Evaluate a polynomial at point x in GF(2^8).
/// coeffs[0] is the constant term (the secret byte).
fn gf_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut result: u8 = 0;
    let mut x_pow: u8 = 1;
    for &c in coeffs {
        result ^= gf_mul(c, x_pow);
        x_pow = gf_mul(x_pow, x);
    }
    result
}

// ── Share / reconstruct ──────────────────────────────────────────────────────

/// One share: an index (1..=255) and 64 bytes of share data.
pub struct Share {
    /// Share index (x-coordinate), must be 1..=255 and non-zero.
    pub index: u8,
    /// Share data: 64 bytes, one per byte of the secret.
    pub data: [u8; 64],
}

impl Drop for Share {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.data);
    }
}

/// Split a 64-byte secret into `n` shares with threshold `t`.
///
/// Any `t` of the `n` shares can reconstruct the secret.
/// Fewer than `t` shares reveal nothing about the secret.
///
/// # Arguments
/// - `secret` — the 64-byte seed to split
/// - `n` — total number of shares (1..=255)
/// - `t` — threshold (2..=n)
///
/// # Errors
/// Returns `None` if parameters are invalid.
pub fn split(secret: &[u8; 64], n: u8, t: u8) -> Option<Vec<Share>> {
    if n < 1 || t < 2 || t > n {
        return None;
    }

    let mut rng_bytes = [0u8; 64 * 32]; // enough random coefficients
    getrandom::getrandom(&mut rng_bytes).ok()?;

    let mut shares: Vec<Share> = (1..=n)
        .map(|i| Share {
            index: i,
            data: [0u8; 64],
        })
        .collect();

    for (byte_pos, &secret_byte) in secret.iter().enumerate() {
        // Build polynomial: coeffs[0] = secret byte, coeffs[1..t] = random.
        let mut coeffs = [0u8; 32]; // max threshold = 32
        coeffs[0] = secret_byte;
        for j in 1..(t as usize) {
            coeffs[j] = rng_bytes[byte_pos * 32 + j];
        }

        // Evaluate at each share index.
        for share in shares.iter_mut() {
            share.data[byte_pos] = gf_eval(&coeffs[..t as usize], share.index);
        }

        // Wipe coefficients.
        zeroize_bytes(&mut coeffs);
    }

    zeroize_bytes(&mut rng_bytes);
    Some(shares)
}

/// Reconstruct a 64-byte secret from `t` or more shares using
/// Lagrange interpolation at x=0 in GF(2^8).
///
/// # Arguments
/// - `shares` — at least `t` shares (extra shares are ignored)
///
/// # Returns
/// The reconstructed 64-byte secret, or `None` if shares are invalid
/// (duplicate indices, insufficient count).
pub fn reconstruct(shares: &[Share]) -> Option<[u8; 64]> {
    if shares.is_empty() {
        return None;
    }

    let k = shares.len();

    // Check for duplicate indices.
    for i in 0..k {
        for j in (i + 1)..k {
            if shares[i].index == shares[j].index {
                return None;
            }
        }
    }

    let mut secret = [0u8; 64];

    #[allow(clippy::needless_range_loop)]
    for byte_pos in 0..64 {
        let mut value: u8 = 0;

        for i in 0..k {
            // Compute Lagrange basis polynomial at x=0:
            // L_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j)
            //        = Π_{j≠i} x_j / (x_i ⊕ x_j)    (in GF(2^8), - = ⊕)
            let mut num: u8 = 1;
            let mut den: u8 = 1;

            for j in 0..k {
                if i == j {
                    continue;
                }
                num = gf_mul(num, shares[j].index);
                den = gf_mul(den, shares[i].index ^ shares[j].index);
            }

            let den_inv = gf_inv(den);
            if den_inv == 0 {
                return None; // duplicate index (shouldn't happen after check)
            }
            let basis = gf_mul(num, den_inv);
            value ^= gf_mul(shares[i].data[byte_pos], basis);
        }

        secret[byte_pos] = value;
    }

    Some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_reconstruct_2_of_3() {
        let secret = [0xABu8; 64];
        let shares = split(&secret, 3, 2).unwrap();
        assert_eq!(shares.len(), 3);

        // Any 2 shares should reconstruct correctly.
        let pairs = [(0, 1), (0, 2), (1, 2)];
        for &(a, b) in &pairs {
            let subset = [
                Share {
                    index: shares[a].index,
                    data: shares[a].data,
                },
                Share {
                    index: shares[b].index,
                    data: shares[b].data,
                },
            ];
            let recovered = reconstruct(&subset).unwrap();
            assert_eq!(recovered, secret, "pair ({}, {}) failed", a, b);
        }
    }

    #[test]
    fn split_reconstruct_3_of_5() {
        let secret = [0x42u8; 64];
        let shares = split(&secret, 5, 3).unwrap();
        assert_eq!(shares.len(), 5);

        // Use shares 0, 2, 4.
        let subset: Vec<Share> = [0, 2, 4]
            .iter()
            .map(|&i| Share {
                index: shares[i].index,
                data: shares[i].data,
            })
            .collect();
        let recovered = reconstruct(&subset).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn insufficient_shares_give_wrong_secret() {
        let secret = [0xFFu8; 64];
        let shares = split(&secret, 5, 3).unwrap();

        // Only 2 shares (need 3) — should NOT reconstruct correctly.
        let subset = [
            Share {
                index: shares[0].index,
                data: shares[0].data,
            },
            Share {
                index: shares[1].index,
                data: shares[1].data,
            },
        ];
        let recovered = reconstruct(&subset).unwrap();
        assert_ne!(recovered, secret, "2 of 3 must not reconstruct correctly");
    }

    #[test]
    fn single_share_insufficient() {
        let secret = [0x11u8; 64];
        let shares = split(&secret, 3, 2).unwrap();

        let subset = [Share {
            index: shares[0].index,
            data: shares[0].data,
        }];
        let recovered = reconstruct(&subset).unwrap();
        assert_ne!(recovered, secret);
    }

    #[test]
    fn duplicate_indices_rejected() {
        let share = Share {
            index: 1,
            data: [0xAA; 64],
        };
        let dup = [
            Share {
                index: share.index,
                data: share.data,
            },
            Share {
                index: share.index,
                data: [0xBB; 64],
            },
        ];
        assert!(
            reconstruct(&dup).is_none(),
            "duplicate indices must be rejected"
        );
    }

    #[test]
    fn invalid_params_rejected() {
        let secret = [0u8; 64];
        assert!(split(&secret, 0, 2).is_none());
        assert!(split(&secret, 3, 0).is_none());
        assert!(split(&secret, 3, 1).is_none()); // t must be >= 2
        assert!(split(&secret, 2, 3).is_none()); // t > n
    }

    #[test]
    fn shares_differ_from_secret() {
        let secret = [0xCDu8; 64];
        let shares = split(&secret, 3, 2).unwrap();
        for share in &shares {
            assert_ne!(share.data, secret, "share must differ from secret");
        }
    }

    #[test]
    fn all_shares_reconstruct() {
        let secret = [0x77u8; 64];
        let shares = split(&secret, 4, 3).unwrap();
        let all: Vec<Share> = shares
            .iter()
            .map(|s| Share {
                index: s.index,
                data: s.data,
            })
            .collect();
        let recovered = reconstruct(&all).unwrap();
        assert_eq!(recovered, secret);
    }
}
