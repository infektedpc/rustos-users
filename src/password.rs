//! Password storage: salted, iterated SHA-256, implemented in-repo.
//!
//! Stored format (one line, parseable, never contains the password):
//!
//! ```text
//! sha256iter$<iterations>$<salt hex>$<digest hex>
//! ```
//!
//! * `iterations` — decimal, e.g. `10000`. The digest is computed by
//!   hashing `salt || password` once, then re-hashing the previous
//!   digest `iterations - 1` more times (each round hashes the raw
//!   32-byte digest, not its hex form).
//! * `salt` — 16 bytes (32 hex chars) by convention; any even-length
//!   hex string of 1..=64 bytes is accepted on parse. The salt must
//!   come from the caller (the kernel supplies entropy, e.g. from the
//!   timer/RDRAND); this crate has no RNG of its own. [`Salt::randomish`]
//!   is a *test-only* deterministic helper, not a source of entropy.
//! * `digest` — 32 bytes, hex encoded.
//!
//! Security position (read the README): this is a simple iterated
//! hash, **not** a memory-hard KDF such as Argon2 or scrypt, and it
//! has no password-strength policy beyond a minimum length of 8.
//! It exists because no hashing crate is available offline; a real
//! KDF should replace it before any password protects real data.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::sha256::{hex_decode, hex_encode, sha256};

/// Default iteration count for new passwords.
pub const DEFAULT_ITERATIONS: u32 = 10_000;
/// Minimum accepted password length (characters, ASCII count here).
pub const MIN_PASSWORD_LEN: usize = 8;
/// Maximum password length accepted (avoids unbounded hashing work).
pub const MAX_PASSWORD_LEN: usize = 256;
/// Salt length used by [`Salt::randomish`] and recommended to callers.
pub const SALT_LEN: usize = 16;

/// Errors from password hashing / verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    /// Password is shorter than [`MIN_PASSWORD_LEN`] or longer than
    /// [`MAX_PASSWORD_LEN`].
    BadLength,
    /// The stored hash string does not parse (bad algorithm tag,
    /// bad iteration count, bad hex, wrong field count).
    MalformedStoredHash,
    /// Iteration count is zero or absurdly large.
    BadIterations,
    /// Salt is empty, odd-length hex, or longer than 64 bytes.
    BadSalt,
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordError::BadLength => write!(f, "password length out of range"),
            PasswordError::MalformedStoredHash => write!(f, "malformed stored password hash"),
            PasswordError::BadIterations => write!(f, "bad iteration count"),
            PasswordError::BadSalt => write!(f, "bad salt"),
        }
    }
}

/// A caller-supplied salt (raw bytes). The kernel must obtain these
/// from real entropy; this type is just a carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Salt(pub Vec<u8>);

impl Salt {
    /// Build a salt from raw bytes. Empty salts are rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PasswordError> {
        if bytes.is_empty() || bytes.len() > 64 {
            return Err(PasswordError::BadSalt);
        }
        Ok(Salt(bytes.to_vec()))
    }

    /// Deterministic salt derived from a seed string. **Test/demo use
    /// only** — it is not random and must never be used for real
    /// accounts. Exists so host tests and the shell can create an
    /// account without an entropy source.
    pub fn randomish(seed: &str) -> Self {
        let mut salt = [0u8; SALT_LEN];
        let mut state: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
        for &b in seed.as_bytes() {
            state ^= b as u64;
            state = state.wrapping_mul(0x100000001b3);
        }
        for (i, slot) in salt.iter_mut().enumerate() {
            state ^= (i as u64).wrapping_mul(0x9e3779b97f4a7c15);
            state = state.wrapping_mul(0x100000001b3);
            *slot = (state >> 32) as u8 ^ state as u8;
        }
        Salt(salt.to_vec())
    }
}

fn check_password_len(password: &str) -> Result<(), PasswordError> {
    let len = password.chars().count();
    if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&len) {
        return Err(PasswordError::BadLength);
    }
    Ok(())
}

/// Hash `password` with `salt` for `iterations` rounds and return the
/// stored-format string `sha256iter$<iters>$<salt hex>$<digest hex>`.
pub fn hash_password(
    password: &str,
    salt: &Salt,
    iterations: u32,
) -> Result<String, PasswordError> {
    check_password_len(password)?;
    if iterations == 0 || iterations > 1_000_000 {
        return Err(PasswordError::BadIterations);
    }
    let digest = hash_password_raw(password, &salt.0, iterations);
    Ok(alloc::format!(
        "sha256iter${}${}${}",
        iterations,
        hex_encode(&salt.0),
        hex_encode(&digest)
    ))
}

/// Raw iterated digest, without the format wrapper.
fn hash_password_raw(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut input = Vec::with_capacity(salt.len() + password.len());
    input.extend_from_slice(salt);
    input.extend_from_slice(password.as_bytes());
    let mut digest = sha256(&input);
    for _ in 1..iterations {
        digest = sha256(&digest);
    }
    digest
}

/// Verify `password` against a stored hash string. Returns `Ok(false)`
/// (not an error) when the password simply does not match; returns
/// `Err` only when the stored string itself is malformed.
pub fn verify_password(password: &str, stored: &str) -> Result<bool, PasswordError> {
    let (iterations, salt, expected) = parse_stored(stored)?;
    if password.chars().count() > MAX_PASSWORD_LEN {
        return Ok(false);
    }
    let digest = hash_password_raw(password, &salt, iterations);
    Ok(constant_time_eq(&digest, &expected))
}

/// Parse a stored hash into (iterations, salt bytes, digest bytes).
fn parse_stored(stored: &str) -> Result<(u32, Vec<u8>, [u8; 32]), PasswordError> {
    let mut parts = stored.split('$');
    let algo = parts.next().ok_or(PasswordError::MalformedStoredHash)?;
    if algo != "sha256iter" {
        return Err(PasswordError::MalformedStoredHash);
    }
    let iters_s = parts.next().ok_or(PasswordError::MalformedStoredHash)?;
    let salt_s = parts.next().ok_or(PasswordError::MalformedStoredHash)?;
    let hash_s = parts.next().ok_or(PasswordError::MalformedStoredHash)?;
    if parts.next().is_some() {
        return Err(PasswordError::MalformedStoredHash);
    }
    let iterations: u32 = iters_s
        .parse()
        .map_err(|_| PasswordError::MalformedStoredHash)?;
    if iterations == 0 || iterations > 1_000_000 {
        return Err(PasswordError::BadIterations);
    }
    let mut salt = [0u8; 64];
    let salt_len = hex_decode(salt_s, &mut salt).ok_or(PasswordError::BadSalt)?;
    if salt_len == 0 {
        return Err(PasswordError::BadSalt);
    }
    let mut digest = [0u8; 32];
    if hex_decode(hash_s, &mut digest) != Some(32) {
        return Err(PasswordError::MalformedStoredHash);
    }
    Ok((iterations, salt[..salt_len].to_vec(), digest))
}

/// Constant-time equality for digests (no early exit on mismatch).
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_right_password_rejects_wrong() {
        let salt = Salt::from_bytes(b"test-salt-16-bytes").unwrap();
        let stored = hash_password("correct horse", &salt, 100).unwrap();
        assert!(verify_password("correct horse", &stored).unwrap());
        assert!(!verify_password("correct hors", &stored).unwrap());
        assert!(!verify_password("Correct horse", &stored).unwrap());
        assert!(!verify_password("", &stored).unwrap());
    }

    #[test]
    fn same_password_different_salt_different_hash() {
        let a = hash_password("hunter2!", &Salt::from_bytes(b"aaaaaaaaaaaaaaaa").unwrap(), 50)
            .unwrap();
        let b = hash_password("hunter2!", &Salt::from_bytes(b"bbbbbbbbbbbbbbbb").unwrap(), 50)
            .unwrap();
        assert_ne!(a, b);
        assert!(verify_password("hunter2!", &a).unwrap());
        assert!(verify_password("hunter2!", &b).unwrap());
    }

    #[test]
    fn iterations_change_the_hash() {
        let salt = Salt::from_bytes(b"iter-salt-123456").unwrap();
        let a = hash_password("password123", &salt, 1).unwrap();
        let b = hash_password("password123", &salt, 2).unwrap();
        assert_ne!(a, b);
        assert!(verify_password("password123", &a).unwrap());
        assert!(verify_password("password123", &b).unwrap());
    }

    #[test]
    fn tampered_salt_or_hash_fails_verification() {
        let salt = Salt::from_bytes(b"tamper-salt-1234").unwrap();
        let stored = hash_password("s3cretpass", &salt, 100).unwrap();
        // Flip one hex digit of the digest.
        let mut chars: Vec<char> = stored.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        let tampered: String = chars.into_iter().collect();
        assert!(!verify_password("s3cretpass", &tampered).unwrap());
        // Flip one hex digit of the salt.
        let mut chars: Vec<char> = stored.chars().collect();
        let salt_pos = stored.find('$').unwrap() + 1;
        let salt_pos = stored[salt_pos..].find('$').unwrap() + salt_pos + 1;
        chars[salt_pos] = if chars[salt_pos] == '0' { '1' } else { '0' };
        let tampered: String = chars.into_iter().collect();
        assert!(!verify_password("s3cretpass", &tampered).unwrap());
    }

    #[test]
    fn malformed_stored_strings_are_errors() {
        assert_eq!(
            verify_password("whatever1", "plaintext"),
            Err(PasswordError::MalformedStoredHash)
        );
        assert_eq!(
            verify_password("whatever1", "argon2$100$abcd$abcd"),
            Err(PasswordError::MalformedStoredHash)
        );
        assert_eq!(
            verify_password("whatever1", "sha256iter$0$abcd$abcd"),
            Err(PasswordError::BadIterations)
        );
        assert_eq!(
            verify_password("whatever1", "sha256iter$100$zz$abcd"),
            Err(PasswordError::BadSalt)
        );
        assert_eq!(
            verify_password("whatever1", "sha256iter$100$abcd$abcd"),
            Err(PasswordError::MalformedStoredHash)
        );
        assert_eq!(
            verify_password("whatever1", "sha256iter$100$abcd$abcd$extra"),
            Err(PasswordError::MalformedStoredHash)
        );
    }

    #[test]
    fn short_password_rejected_at_hash_time() {
        let salt = Salt::from_bytes(b"short-salt-12345").unwrap();
        assert_eq!(
            hash_password("tiny", &salt, 100),
            Err(PasswordError::BadLength)
        );
        assert_eq!(
            hash_password("", &salt, 100),
            Err(PasswordError::BadLength)
        );
        // Exactly 8 chars is fine.
        assert!(hash_password("12345678", &salt, 10).is_ok());
    }

    #[test]
    fn format_is_documented_and_parseable() {
        let salt = Salt::from_bytes(b"0123456789abcdef").unwrap();
        let stored = hash_password("my password", &salt, 1234).unwrap();
        assert!(stored.starts_with("sha256iter$1234$30313233343536373839616263646566$"));
        let (iters, s, d) = parse_stored(&stored).unwrap();
        assert_eq!(iters, 1234);
        assert_eq!(s, b"0123456789abcdef");
        assert_eq!(d.len(), 32);
    }

    #[test]
    fn randomish_salt_is_stable_and_usable() {
        let a = Salt::randomish("root");
        let b = Salt::randomish("root");
        assert_eq!(a, b);
        assert_ne!(a, Salt::randomish("alice"));
        let stored = hash_password("some password", &a, 10).unwrap();
        assert!(verify_password("some password", &stored).unwrap());
    }
}
